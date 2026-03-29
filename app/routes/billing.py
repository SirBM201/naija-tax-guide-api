from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan, list_plans
from app.services.web_auth_service import get_account_id_from_request
from app.services.paystack_service import (
    create_reference,
    initialize_transaction,
    verify_transaction,
    verify_webhook_signature,
)
from app.services.credits_service import (
    init_credits_for_plan,
    get_credit_balance_details,
    get_daily_usage,
)
from app.services.subscription_guard import get_subscription_snapshot
from app.services.referral_service import ensure_referral_profile, qualify_referral_after_successful_payment
from app.services.channel_post_payment_service import notify_channel_payment_success

bp = Blueprint("billing", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _safe_json() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _clip(v: Any, n: int = 400) -> str:
    s = str(v or "")
    return s if len(s) <= n else s[:n] + "...<truncated>"


def _safe_dt(v: Any) -> Optional[datetime]:
    try:
        if not v:
            return None
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _fail(*, error: str, root_cause: Any = None, extra: Dict[str, Any] | None = None, status: int = 400):
    out: Dict[str, Any] = {"ok": False, "error": error}
    if root_cause is not None:
        out["root_cause"] = root_cause
    if extra:
        out.update(extra)
    return jsonify(out), status


def _store_paystack_event(
    *,
    event_id: Optional[str],
    event_type: str,
    reference: Optional[str],
    payload: Dict[str, Any],
) -> None:
    row = {
        "event_id": event_id,
        "event_type": event_type or "unknown",
        "reference": reference,
        "payload": payload,
        "created_at": _now_iso(),
    }
    try:
        _sb().table("paystack_events").insert(row).execute()
    except Exception:
        pass


def _get_account_row(account_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    account_id here is canonical accounts.account_id from web auth.
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return None, {"error": "account_id_required", "root_cause": "missing_account_id"}

    try:
        q = (
            _sb()
            .table("accounts")
            .select("id,account_id,email,provider,provider_user_id,display_name,created_at,updated_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
        if rows:
            return rows[0], None
    except Exception as e:
        return None, {
            "error": "account_lookup_failed",
            "root_cause": f"lookup by account_id failed: {type(e).__name__}: {_clip(e)}",
        }

    try:
        q = (
            _sb()
            .table("accounts")
            .select("id,account_id,email,provider,provider_user_id,display_name,created_at,updated_at")
            .eq("id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
        if rows:
            return rows[0], None
    except Exception as e:
        return None, {
            "error": "account_lookup_failed",
            "root_cause": f"lookup by id failed: {type(e).__name__}: {_clip(e)}",
        }

    return None, {"error": "account_not_found", "root_cause": "no accounts row matched provided account_id"}


def _resolve_checkout_email(account_id: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    row, err = _get_account_row(account_id)
    if err:
        return None, err

    email = (row.get("email") or "").strip().lower()
    if "@" in email:
        return email, None

    provider = (row.get("provider") or "").strip().lower()
    provider_user_id = (row.get("provider_user_id") or "").strip().lower()
    if provider == "web" and "@" in provider_user_id:
        return provider_user_id, None

    return None, {
        "error": "checkout_email_missing",
        "root_cause": "No valid email found on accounts.email or provider_user_id",
        "details": {
            "account_id": account_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "email": email,
        },
        "fix": "Ensure accounts.email is populated for this authenticated account.",
    }


def _get_subscription_row(account_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    account_id = (account_id or "").strip()
    if not account_id:
        return None, {"error": "account_id_required", "root_cause": "missing_account_id"}

    try:
        q = (
            _sb()
            .table("user_subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
        return (rows[0] if rows else None), None
    except Exception as e:
        return None, {
            "error": "subscription_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _subscription_is_active_now(sub: Optional[Dict[str, Any]]) -> bool:
    if not sub:
        return False

    status = str(sub.get("status") or "").strip().lower()
    is_active = bool(sub.get("is_active"))
    expires_at = _safe_dt(sub.get("expires_at"))
    grace_until = _safe_dt(sub.get("grace_until"))

    now = _now()

    if not is_active or status != "active":
        return False

    if expires_at and now < expires_at:
        return True

    if grace_until and now < grace_until:
        return True

    return expires_at is None


def _plan_sort_tuple(plan: Dict[str, Any]) -> Tuple[int, int]:
    """
    Compare plans in a deterministic way:
    1. higher price is considered higher tier
    2. if price matches, longer duration is considered higher tier
    """
    price = int(plan.get("price") or 0)
    duration = int(plan.get("duration_days") or 0)
    return (price, duration)


def _compare_plan_tier(current_plan: Dict[str, Any], target_plan: Dict[str, Any]) -> int:
    """
    Returns:
      1  -> target is higher tier than current
      0  -> same tier
      -1 -> target is lower tier than current
    """
    a = _plan_sort_tuple(current_plan)
    b = _plan_sort_tuple(target_plan)

    if b > a:
        return 1
    if b < a:
        return -1
    return 0


def _derive_change_mode(current_plan_code: Optional[str], target_plan_code: str) -> str:
    current_plan_code = (current_plan_code or "").strip().lower()
    target_plan_code = (target_plan_code or "").strip().lower()

    if not current_plan_code:
        return "new_purchase"

    current_plan = get_plan(current_plan_code)
    target_plan = get_plan(target_plan_code)

    if not current_plan or not target_plan:
        return "unknown"

    cmp = _compare_plan_tier(current_plan, target_plan)
    if cmp > 0:
        return "upgrade_now"
    if cmp < 0:
        return "downgrade_at_period_end"
    return "same_plan"


def _same_active_plan_guard(account_id: str, requested_plan_code: str) -> Optional[Tuple[Any, int]]:
    sub, err = _get_subscription_row(account_id)
    if err:
        return None

    if not sub:
        return None

    current_plan_code = (sub.get("plan_code") or "").strip().lower()
    requested_plan_code = (requested_plan_code or "").strip().lower()
    same_plan = current_plan_code and current_plan_code == requested_plan_code

    if same_plan and _subscription_is_active_now(sub):
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "same_active_plan_exists",
                    "root_cause": "requested_plan_matches_current_active_plan",
                    "fix": "Use billing page to review the current subscription instead of purchasing the same active plan again.",
                    "details": {
                        "account_id": account_id,
                        "current_subscription": {
                            "id": sub.get("id"),
                            "plan_code": sub.get("plan_code"),
                            "status": sub.get("status"),
                            "is_active": sub.get("is_active"),
                            "expires_at": sub.get("expires_at"),
                            "provider": sub.get("provider"),
                            "provider_ref": sub.get("provider_ref"),
                            "pending_plan_code": sub.get("pending_plan_code"),
                            "pending_starts_at": sub.get("pending_starts_at"),
                        },
                    },
                }
            ),
            409,
        )

    return None


def _build_subscription_summary(sub: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not sub:
        return {
            "has_subscription": False,
            "is_active_now": False,
            "has_pending_change": False,
            "current_plan_code": None,
            "pending_plan_code": None,
            "pending_starts_at": None,
        }

    return {
        "has_subscription": True,
        "is_active_now": _subscription_is_active_now(sub),
        "has_pending_change": bool(sub.get("pending_plan_code")),
        "current_plan_code": sub.get("plan_code"),
        "pending_plan_code": sub.get("pending_plan_code"),
        "pending_starts_at": sub.get("pending_starts_at"),
        "status": sub.get("status"),
        "is_active": sub.get("is_active"),
        "started_at": sub.get("started_at"),
        "expires_at": sub.get("expires_at"),
        "current_period_end": sub.get("current_period_end"),
        "provider": sub.get("provider"),
        "provider_ref": sub.get("provider_ref"),
    }


def _init_plan_credits_safe(account_id: str, plan_code: str) -> Dict[str, Any]:
    """
    Best-effort credit initialization after successful plan activation.
    Does not throw.
    """
    try:
        res = init_credits_for_plan(account_id, plan_code)
        return res if isinstance(res, dict) else {"ok": False, "error": "credit_init_unknown_result"}
    except Exception as e:
        return {
            "ok": False,
            "error": "credit_init_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "details": {"account_id": account_id, "plan_code": plan_code},
        }


def _upsert_user_subscription(
    *,
    account_id: str,
    plan_code: str,
    duration_days: int,
    provider: str,
    provider_ref: str,
) -> Dict[str, Any]:
    """
    user_subscriptions uses canonical account_id (accounts.account_id).
    This is used when a paid checkout succeeds and the new plan becomes active immediately.
    """
    now = _now()
    expires = now + timedelta(days=int(duration_days))
    now_iso = now.isoformat()
    exp_iso = expires.isoformat()

    existing = (
        _sb()
        .table("user_subscriptions")
        .select("id,account_id,plan_code,status,is_active,expires_at,pending_plan_code,pending_starts_at")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    rows = getattr(existing, "data", None) or []

    patch = {
        "plan_code": plan_code,
        "status": "active",
        "is_active": True,
        "started_at": now_iso,
        "expires_at": exp_iso,
        "current_period_end": exp_iso,
        "provider": provider,
        "provider_ref": provider_ref,
        "pending_plan_code": None,
        "pending_starts_at": None,
        "updated_at": now_iso,
    }

    if rows:
        sub_id = rows[0]["id"]
        upd = _sb().table("user_subscriptions").update(patch).eq("id", sub_id).execute()
        out = getattr(upd, "data", None) or []
        return out[0] if out else {"id": sub_id, "account_id": account_id, **patch}

    ins = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": "active",
        "is_active": True,
        "started_at": now_iso,
        "expires_at": exp_iso,
        "current_period_end": exp_iso,
        "provider": provider,
        "provider_ref": provider_ref,
        "pending_plan_code": None,
        "pending_starts_at": None,
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    created = _sb().table("user_subscriptions").insert(ins).execute()
    out = getattr(created, "data", None) or []
    return out[0] if out else ins


def _schedule_downgrade(
    *,
    account_id: str,
    target_plan_code: str,
    current_sub: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    sub_id = str(current_sub.get("id") or "").strip()
    if not sub_id:
        return None, {"error": "subscription_id_missing", "root_cause": "current_subscription_missing_id"}

    target_plan_code = (target_plan_code or "").strip().lower()
    existing_pending = (current_sub.get("pending_plan_code") or "").strip().lower()
    pending_starts_at = current_sub.get("pending_starts_at")
    current_period_end = current_sub.get("current_period_end") or current_sub.get("expires_at")

    if existing_pending == target_plan_code and pending_starts_at:
        return None, {
            "error": "downgrade_already_scheduled",
            "root_cause": "same_pending_plan_already_exists",
            "details": {
                "pending_plan_code": existing_pending,
                "pending_starts_at": pending_starts_at,
            },
        }

    if not current_period_end:
        return None, {
            "error": "current_period_end_missing",
            "root_cause": "cannot_schedule_downgrade_without_current_period_end",
        }

    patch = {
        "pending_plan_code": target_plan_code,
        "pending_starts_at": current_period_end,
        "updated_at": _now_iso(),
    }

    try:
        upd = _sb().table("user_subscriptions").update(patch).eq("id", sub_id).execute()
        out = getattr(upd, "data", None) or []
        row = out[0] if out else {**current_sub, **patch}
        return row, None
    except Exception as e:
        return None, {
            "error": "downgrade_schedule_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _clear_pending_change(
    *,
    sub_id: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    if not sub_id:
        return None, {"error": "subscription_id_missing", "root_cause": "missing_sub_id"}

    patch = {
        "pending_plan_code": None,
        "pending_starts_at": None,
        "updated_at": _now_iso(),
    }

    try:
        upd = _sb().table("user_subscriptions").update(patch).eq("id", sub_id).execute()
        out = getattr(upd, "data", None) or []
        row = out[0] if out else patch
        return row, None
    except Exception as e:
        return None, {
            "error": "pending_change_clear_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
        }


def _start_checkout_for_plan_change(
    *,
    account_id: str,
    plan_code: str,
    change_mode: str,
    current_plan_code: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    plan = get_plan(plan_code)
    if not plan or not plan.get("active", True):
        return None, {"error": "plan_not_found", "root_cause": f"unknown_or_inactive_plan:{plan_code}"}

    price_ngn = int(plan.get("price") or 0)
    if price_ngn <= 0:
        return None, {"error": "plan_price_missing", "root_cause": f"invalid_price_for_plan:{plan_code}"}

    email, email_err = _resolve_checkout_email(account_id)
    if email_err or not email:
        return None, {
            "error": "checkout_email_missing",
            "root_cause": (email_err or {}).get("root_cause"),
            "details": (email_err or {}).get("details"),
            "fix": (email_err or {}).get("fix"),
        }

    reference = create_reference("NTG")
    metadata = {
        "product": "naija_tax_guide",
        "plan_code": plan_code,
        "account_id": account_id,
        "email": email,
        "change_mode": change_mode,
        "current_plan_code": (current_plan_code or "").strip().lower() or None,
    }

    try:
        ps = initialize_transaction(
            email=email,
            amount_kobo=price_ngn * 100,
            reference=reference,
            metadata=metadata,
        )
    except Exception as e:
        return None, {
            "error": "paystack_init_failed",
            "root_cause": repr(e),
            "details": {
                "account_id": account_id,
                "email": email,
                "plan_code": plan_code,
                "change_mode": change_mode,
            },
        }

    data = (ps or {}).get("data") or {}
    return {
        "ok": True,
        "action": "checkout_started",
        "reference": reference,
        "authorization_url": data.get("authorization_url"),
        "access_code": data.get("access_code"),
        "plan": plan,
        "account_id": account_id,
        "email": email,
        "change_mode": change_mode,
    }, None


# -------------------- ROUTES --------------------


@bp.get("/billing/plans")
def billing_plans():
    active_only = (request.args.get("active_only") or "1").strip() != "0"
    plans = list_plans(active_only=active_only)
    return jsonify({"ok": True, "plans": plans}), 200


@bp.get("/billing/plans/<plan_code>")
def billing_plan(plan_code: str):
    p = get_plan(plan_code)
    if not p:
        return jsonify({"ok": False, "error": "plan_not_found"}), 404
    return jsonify({"ok": True, "plan": p}), 200


@bp.get("/billing/me")
@bp.get("/billing/subscription")
def billing_me():
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    sub = None
    db_warning = None
    try:
        q = (
            _sb()
            .table("user_subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
        sub = rows[0] if rows else None
    except Exception as e:
        db_warning = repr(e)

    checkout_email, email_err = _resolve_checkout_email(account_id)
    summary = _build_subscription_summary(sub)

    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "subscription": sub,
            "subscription_summary": summary,
            "checkout_email": checkout_email,
            "checkout_email_error": email_err,
            "db_warning": db_warning,
            "debug": debug,
        }
    ), 200


@bp.get("/billing/debug-state")
def billing_debug_state():
    """
    Unified monetization state inspector.
    Helps verify auth -> subscription -> credits -> daily usage in one response.
    """
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    sub, sub_err = _get_subscription_row(account_id)
    checkout_email, email_err = _resolve_checkout_email(account_id)
    summary = _build_subscription_summary(sub)
    guard = get_subscription_snapshot(account_id)
    credit_details = get_credit_balance_details(account_id)
    usage_today = get_daily_usage(account_id)

    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "subscription": sub,
            "subscription_error": sub_err,
            "subscription_summary": summary,
            "subscription_guard_snapshot": guard,
            "checkout_email": checkout_email,
            "checkout_email_error": email_err,
            "credit_balance": credit_details,
            "daily_usage_today": usage_today,
            "debug": debug,
        }
    ), 200


@bp.post("/billing/checkout")
def billing_checkout():
    """
    Start Paystack transaction.
    Email is resolved automatically from the authenticated account.
    Body:
      { "plan_code": "monthly|quarterly|yearly" }
    """
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    body = _safe_json()
    plan_code = (body.get("plan_code") or "").strip().lower()

    if not plan_code:
        return _fail(error="plan_code_required", status=400)

    plan = get_plan(plan_code)
    if not plan or not plan.get("active", True):
        return _fail(error="plan_not_found", status=404)

    same_plan_block = _same_active_plan_guard(account_id, plan_code)
    if same_plan_block is not None:
        return same_plan_block

    sub, _ = _get_subscription_row(account_id)
    current_plan_code = (sub or {}).get("plan_code")
    change_mode = _derive_change_mode(current_plan_code, plan_code)

    started, err = _start_checkout_for_plan_change(
        account_id=account_id,
        plan_code=plan_code,
        change_mode=change_mode if change_mode != "same_plan" else "new_purchase",
        current_plan_code=current_plan_code,
    )
    if err:
        return _fail(
            error=err.get("error") or "checkout_failed",
            root_cause=err.get("root_cause"),
            extra={
                "details": err.get("details"),
                "fix": err.get("fix"),
                "account_id": account_id,
            },
            status=400,
        )

    return jsonify(started), 200


@bp.post("/billing/change-plan")
def billing_change_plan():
    """
    Intelligent plan-change endpoint.

    Behavior:
    - same active plan -> blocked
    - higher tier than current active plan -> Paystack checkout starts immediately
    - lower tier than current active plan -> schedule pending downgrade at current_period_end
    - no active subscription -> treated as fresh checkout
    """
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    body = _safe_json()
    target_plan_code = (body.get("plan_code") or "").strip().lower()
    if not target_plan_code:
        return _fail(error="plan_code_required", status=400)

    target_plan = get_plan(target_plan_code)
    if not target_plan or not target_plan.get("active", True):
        return _fail(error="plan_not_found", status=404)

    sub, sub_err = _get_subscription_row(account_id)
    if sub_err:
        return _fail(
            error=sub_err.get("error") or "subscription_lookup_failed",
            root_cause=sub_err.get("root_cause"),
            status=400,
        )

    same_plan_block = _same_active_plan_guard(account_id, target_plan_code)
    if same_plan_block is not None:
        return same_plan_block

    current_active = _subscription_is_active_now(sub)
    current_plan_code = (sub or {}).get("plan_code")
    change_mode = _derive_change_mode(current_plan_code, target_plan_code)

    if not sub or not current_active or not current_plan_code:
        started, err = _start_checkout_for_plan_change(
            account_id=account_id,
            plan_code=target_plan_code,
            change_mode="new_purchase",
            current_plan_code=current_plan_code,
        )
        if err:
            return _fail(
                error=err.get("error") or "checkout_failed",
                root_cause=err.get("root_cause"),
                extra={
                    "details": err.get("details"),
                    "fix": err.get("fix"),
                    "account_id": account_id,
                },
                status=400,
            )
        return jsonify(started), 200

    if change_mode == "upgrade_now":
        started, err = _start_checkout_for_plan_change(
            account_id=account_id,
            plan_code=target_plan_code,
            change_mode="upgrade_now",
            current_plan_code=current_plan_code,
        )
        if err:
            return _fail(
                error=err.get("error") or "checkout_failed",
                root_cause=err.get("root_cause"),
                extra={
                    "details": err.get("details"),
                    "fix": err.get("fix"),
                    "account_id": account_id,
                },
                status=400,
            )
        return jsonify(started), 200

    if change_mode == "downgrade_at_period_end":
        updated_sub, err = _schedule_downgrade(
            account_id=account_id,
            target_plan_code=target_plan_code,
            current_sub=sub,
        )
        if err:
            status_code = 409 if err.get("error") == "downgrade_already_scheduled" else 400
            return _fail(
                error=err.get("error") or "downgrade_schedule_failed",
                root_cause=err.get("root_cause"),
                extra={"details": err.get("details")},
                status=status_code,
            )

        return jsonify(
            {
                "ok": True,
                "action": "downgrade_scheduled",
                "message": "Your lower-tier plan has been scheduled for the end of the current billing period.",
                "subscription": updated_sub,
                "subscription_summary": _build_subscription_summary(updated_sub),
                "target_plan": target_plan,
            }
        ), 200

    return _fail(
        error="plan_change_mode_unknown",
        root_cause=f"could_not_resolve_change_mode:{change_mode}",
        extra={
            "current_plan_code": current_plan_code,
            "target_plan_code": target_plan_code,
        },
        status=400,
    )


@bp.post("/billing/clear-pending-change")
def billing_clear_pending_change():
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    sub, sub_err = _get_subscription_row(account_id)
    if sub_err:
        return _fail(
            error=sub_err.get("error") or "subscription_lookup_failed",
            root_cause=sub_err.get("root_cause"),
            status=400,
        )

    if not sub:
        return _fail(error="subscription_not_found", status=404)

    if not sub.get("pending_plan_code"):
        return jsonify(
            {
                "ok": True,
                "action": "no_pending_change",
                "subscription": sub,
                "subscription_summary": _build_subscription_summary(sub),
            }
        ), 200

    updated, err = _clear_pending_change(sub_id=str(sub.get("id") or ""))
    if err:
        return _fail(
            error=err.get("error") or "pending_change_clear_failed",
            root_cause=err.get("root_cause"),
            status=400,
        )

    merged = {**sub, **(updated or {})}
    return jsonify(
        {
            "ok": True,
            "action": "pending_change_cleared",
            "subscription": merged,
            "subscription_summary": _build_subscription_summary(merged),
        }
    ), 200


@bp.get("/billing/verify")
def billing_verify():
    """
    Verify a reference after Paystack redirect.
    GET /billing/verify?reference=...
    """
    reference = (request.args.get("reference") or "").strip()
    if not reference:
        return _fail(error="missing_reference", status=400)

    try:
        ps = verify_transaction(reference)
    except Exception as e:
        return _fail(error="paystack_verify_failed", root_cause=repr(e), status=400)

    tx = (ps or {}).get("data") or {}
    status_text = (tx.get("status") or "").strip().lower()
    tx_id = str(tx.get("id") or "") or None
    metadata = tx.get("metadata") or {}

    plan_code = (metadata.get("plan_code") or "").strip().lower()
    account_id = (metadata.get("account_id") or "").strip()
    change_mode = (metadata.get("change_mode") or "").strip().lower() or "new_purchase"

    _store_paystack_event(event_id=tx_id, event_type="verify", reference=reference, payload=ps)

    if status_text != "success":
        return jsonify(
            {
                "ok": True,
                "paid": False,
                "status": status_text,
                "reference": reference,
                "data": tx,
            }
        ), 200

    if not plan_code or not account_id:
        return _fail(
            error="missing_metadata",
            extra={"metadata": metadata, "reference": reference},
            status=400,
        )

    plan = get_plan(plan_code)
    if not plan:
        return _fail(error="plan_not_found", extra={"plan_code": plan_code}, status=404)

    sub = _upsert_user_subscription(
        account_id=account_id,
        plan_code=plan_code,
        duration_days=int(plan["duration_days"]),
        provider="paystack",
        provider_ref=reference,
    )

    credit_init = _init_plan_credits_safe(account_id, plan_code)

    return jsonify(
        {
            "ok": True,
            "paid": True,
            "reference": reference,
            "change_mode": change_mode,
            "subscription": sub,
            "subscription_summary": _build_subscription_summary(sub),
            "plan": plan,
            "credits_initialized": bool(credit_init.get("ok")),
            "credit_init_result": credit_init,
        }
    ), 200


@bp.post("/billing/webhook")
def billing_webhook():
    """
    Paystack webhook:
    - validates signature
    - stores event
    - on charge.success -> activates subscription
    - initializes plan credits
    - ensures referral profile exists
    - sends post-payment channel notification for Telegram / WhatsApp origin payments
    """
    raw_body = request.get_data(cache=False) or b""
    sig = (request.headers.get("x-paystack-signature") or "").strip()

    if not verify_webhook_signature(raw_body, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    payload = request.get_json(silent=True) or {}
    event_type = (payload.get("event") or "").strip().lower()
    data = payload.get("data") or {}
    reference = (data.get("reference") or "").strip() or None
    tx_id = str(data.get("id") or "") or None

    _store_paystack_event(
        event_id=tx_id,
        event_type=event_type or "unknown",
        reference=reference,
        payload=payload,
    )

    result: Dict[str, Any] = {"ok": True, "event_type": event_type, "reference": reference}

    if event_type == "charge.success":
        metadata = data.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        plan_code = (metadata.get("plan_code") or "").strip().lower()
        account_id = (metadata.get("account_id") or "").strip()
        channel_type = (metadata.get("channel_type") or "").strip().lower()
        provider_user_id = (metadata.get("provider_user_id") or "").strip() or None

        result["metadata"] = {
            "account_id": account_id,
            "plan_code": plan_code,
            "channel_type": channel_type,
            "provider_user_id": provider_user_id,
        }

        if plan_code and account_id and reference:
            plan = get_plan(plan_code)
            if plan:
                sub = _upsert_user_subscription(
                    account_id=account_id,
                    plan_code=plan_code,
                    duration_days=int(plan["duration_days"]),
                    provider="paystack",
                    provider_ref=reference,
                )
                credit_init = _init_plan_credits_safe(account_id, plan_code)

                try:
                    referral_profile = ensure_referral_profile(account_id)
                except Exception as e:
                    referral_profile = {
                        "ok": False,
                        "error": "ensure_referral_profile_failed",
                        "root_cause": repr(e),
                    }

                try:
                    referral_qualification = qualify_referral_after_successful_payment(
                        paying_account_id=account_id,
                        payment_reference=reference,
                        plan_code=plan_code,
                    )
                except Exception as e:
                    referral_qualification = {
                        "ok": False,
                        "error": "qualify_referral_after_successful_payment_failed",
                        "root_cause": repr(e),
                    }

                if channel_type in {"telegram", "whatsapp"}:
                    try:
                        channel_notification = notify_channel_payment_success(
                            account_id=account_id,
                            channel_type=channel_type,
                            plan_code=plan_code,
                            provider_user_id=provider_user_id,
                        )
                    except Exception as e:
                        channel_notification = {
                            "ok": False,
                            "error": "channel_notification_failed",
                            "root_cause": repr(e),
                        }
                else:
                    channel_notification = {
                        "ok": True,
                        "skipped": True,
                        "reason": "not_channel_payment",
                        "channel_type": channel_type,
                    }

                result.update(
                    {
                        "subscription": sub,
                        "credits_initialized": credit_init,
                        "ensured_referral_profile": referral_profile,
                        "referral_qualification": referral_qualification,
                        "channel_notification": channel_notification,
                    }
                )
            else:
                result.update({"ok": False, "error": "plan_not_found", "plan_code": plan_code})
        else:
            result.update(
                {
                    "ok": False,
                    "error": "missing_payment_metadata",
                    "account_id": account_id,
                    "plan_code": plan_code,
                    "reference": reference,
                }
            )

    return jsonify(result), 200
