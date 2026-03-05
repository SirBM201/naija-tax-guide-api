# app/routes/billing.py
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

bp = Blueprint("billing", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _debug_enabled() -> bool:
    return _truthy(request.args.get("debug") or "") or _truthy(request.headers.get("X-Debug") or "")


def _safe_json() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _fail(status: int, *, error: str, stage: str, hint: str = "", root_cause: str = "", debug: Any = None, extra=None):
    out: Dict[str, Any] = {"ok": False, "error": error, "stage": stage}
    if hint:
        out["hint"] = hint
    if root_cause:
        out["root_cause"] = root_cause
    if debug is not None:
        out["debug"] = debug
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
    """
    Table expected (recommended):
      paystack_events:
        id bigint pk
        event_id text unique nullable
        event_type text not null
        reference text nullable
        payload jsonb not null
        created_at timestamptz not null

    Best-effort. If table doesn't exist, it won't break payments.
    """
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


def _fetch_account_email(accounts_id: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Fetch email from public.accounts using accounts.id (canonical).
    Returns (email, err_debug).
    """
    try:
        q = (
            _sb()
            .table("accounts")
            .select("id,email,provider,provider_user_id")
            .eq("id", accounts_id)
            .limit(1)
            .execute()
        )
        rows = getattr(q, "data", None) or []
        if not rows:
            return None, {"error": "account_not_found", "accounts_id": accounts_id}
        row = rows[0]
        email = (row.get("email") or "").strip().lower()
        if not email:
            # fallback: for web accounts, provider_user_id is the email
            if (row.get("provider") or "").strip().lower() == "web":
                email = (row.get("provider_user_id") or "").strip().lower()

        if "@" not in email:
            return None, {"error": "account_email_missing", "accounts_id": accounts_id, "row": row}

        return email, None
    except Exception as e:
        return None, {"error": "account_email_lookup_failed", "accounts_id": accounts_id, "exception": repr(e)}


def _upsert_user_subscription(
    *,
    account_id: str,
    plan_code: str,
    duration_days: int,
    provider: str,
    provider_ref: str,
) -> Dict[str, Any]:
    """
    user_subscriptions unique by account_id (one current subscription per account).
    This function will:
      - update existing row if found
      - else insert a new row
    """
    now = _now()
    expires = now + timedelta(days=int(duration_days))
    now_iso = now.isoformat()
    exp_iso = expires.isoformat()

    existing = (
        _sb()
        .table("user_subscriptions")
        .select("id,account_id,plan_code,status,is_active,expires_at")
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
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    created = _sb().table("user_subscriptions").insert(ins).execute()
    out = getattr(created, "data", None) or []
    return out[0] if out else ins


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
def billing_me():
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    sub = None
    err = None
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
        err = repr(e)

    return jsonify({"ok": True, "account_id": account_id, "subscription": sub, "db_warning": err, "debug": debug}), 200


@bp.post("/billing/checkout")
def billing_checkout():
    """
    Start Paystack transaction (requires auth session).
    Body: { "plan_code": "monthly|quarterly|yearly" }

    Backend fetches payer email from public.accounts.
    """
    account_id, auth_debug = get_account_id_from_request(request)
    if not account_id:
        return _fail(
            401,
            error="unauthorized",
            stage="auth",
            hint="Login first. Missing/invalid token or cookie.",
            debug=auth_debug if _debug_enabled() else None,
        )

    body = _safe_json()
    plan_code = (body.get("plan_code") or "").strip().lower()
    if not plan_code:
        return _fail(400, error="plan_code_required", stage="validate_input", hint="Send JSON: {\"plan_code\":\"monthly\"}")

    plan = get_plan(plan_code)
    if not plan or not plan.get("active", True):
        return _fail(404, error="plan_not_found", stage="plan_lookup", extra={"plan_code": plan_code})

    price_ngn = int(plan.get("price") or 0)
    if price_ngn <= 0:
        return _fail(400, error="plan_price_missing", stage="plan_validate", extra={"plan": plan})

    # Fetch email from accounts
    email, email_err = _fetch_account_email(account_id)
    if email_err:
        return _fail(
            400,
            error="payer_email_missing",
            stage="account_email",
            hint="Account exists but email is missing. Ensure accounts.email is populated for this user.",
            debug=email_err if _debug_enabled() else None,
            extra={"account_id": account_id},
        )

    reference = create_reference("NTG")

    metadata = {
        "product": "naija_tax_guide",
        "plan_code": plan_code,
        "account_id": account_id,  # IMPORTANT
        "email": email,
    }

    try:
        ps = initialize_transaction(
            email=email,
            amount_kobo=price_ngn * 100,
            reference=reference,
            metadata=metadata,
        )
    except Exception as e:
        return _fail(
            400,
            error="paystack_init_failed",
            stage="paystack_initialize",
            root_cause=f"{type(e).__name__}: {str(e)}",
            debug={"account_id": account_id, "plan_code": plan_code, "email": email} if _debug_enabled() else None,
        )

    data = (ps or {}).get("data") or {}
    auth_url = data.get("authorization_url")
    if not auth_url:
        return _fail(
            400,
            error="paystack_init_missing_url",
            stage="paystack_initialize",
            root_cause="authorization_url not returned by paystack",
            debug=ps if _debug_enabled() else None,
        )

    return jsonify(
        {
            "ok": True,
            "reference": reference,
            "authorization_url": auth_url,
            "access_code": data.get("access_code"),
            "plan": plan,
            "account_id": account_id,
            "payer_email": email,
        }
    ), 200


@bp.get("/billing/verify")
def billing_verify():
    """
    Verify a reference (after Paystack redirect).
    GET /billing/verify?reference=...
    """
    reference = (request.args.get("reference") or "").strip()
    if not reference:
        return _fail(400, error="missing_reference", stage="validate_input")

    try:
        ps = verify_transaction(reference)
    except Exception as e:
        return _fail(
            400,
            error="paystack_verify_failed",
            stage="paystack_verify",
            root_cause=f"{type(e).__name__}: {str(e)}",
        )

    tx = (ps or {}).get("data") or {}
    status = (tx.get("status") or "").strip().lower()
    tx_id = str(tx.get("id") or "") or None
    metadata = tx.get("metadata") or {}

    plan_code = (metadata.get("plan_code") or "").strip().lower()
    account_id = (metadata.get("account_id") or "").strip()

    _store_paystack_event(event_id=tx_id, event_type="verify", reference=reference, payload=ps)

    if status != "success":
        return jsonify({"ok": True, "paid": False, "status": status, "reference": reference, "data": tx}), 200

    if not plan_code or not account_id:
        return _fail(
            400,
            error="missing_metadata",
            stage="verify_metadata",
            hint="Paystack transaction metadata missing plan_code/account_id.",
            debug={"metadata": metadata, "reference": reference} if _debug_enabled() else None,
        )

    plan = get_plan(plan_code)
    if not plan:
        return _fail(404, error="plan_not_found", stage="plan_lookup", extra={"plan_code": plan_code})

    sub = _upsert_user_subscription(
        account_id=account_id,
        plan_code=plan_code,
        duration_days=int(plan["duration_days"]),
        provider="paystack",
        provider_ref=reference,
    )

    return jsonify({"ok": True, "paid": True, "reference": reference, "subscription": sub, "plan": plan}), 200


@bp.post("/billing/webhook")
def billing_webhook():
    """
    Paystack webhook:
    - validates signature (x-paystack-signature)
    - stores event in paystack_events
    - on charge.success -> activates subscription
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

    _store_paystack_event(event_id=tx_id, event_type=event_type or "unknown", reference=reference, payload=payload)

    if event_type == "charge.success":
        metadata = data.get("metadata") or {}
        plan_code = (metadata.get("plan_code") or "").strip().lower()
        account_id = (metadata.get("account_id") or "").strip()

        if plan_code and account_id and reference:
            plan = get_plan(plan_code)
            if plan:
                _upsert_user_subscription(
                    account_id=account_id,
                    plan_code=plan_code,
                    duration_days=int(plan["duration_days"]),
                    provider="paystack",
                    provider_ref=reference,
                )

    return jsonify({"ok": True}), 200
