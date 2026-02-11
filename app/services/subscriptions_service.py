# app/services/subscriptions_service.py
from __future__ import annotations

from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase
from ..services.credits_service import init_credits_for_plan


# -----------------------------
# Time helpers
# -----------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_provider(provider: Optional[str]) -> Optional[str]:
    if not provider:
        return None
    p = provider.strip().lower()
    if p in ("whatsapp", "wa"):
        return "wa"
    if p in ("telegram", "tg"):
        return "tg"
    if p in ("web", "site", "website"):
        return "web"
    return p


# -----------------------------
# Lookups
# -----------------------------
def _find_account_id(account_id: Optional[str], provider: Optional[str], provider_user_id: Optional[str]) -> Optional[str]:
    if account_id:
        return account_id.strip() or None

    provider = _normalize_provider(provider)

    if not provider or not provider_user_id:
        return None

    db = supabase()
    got = (
        db.table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    if got.data:
        return got.data[0]["id"]
    return None


def _get_plan(plan_code: str) -> Optional[Dict[str, Any]]:
    plan_code = (plan_code or "").strip().lower()
    if not plan_code:
        return None
    db = supabase()
    res = db.table("plans").select("*").eq("plan_code", plan_code).limit(1).execute()
    return res.data[0] if res.data else None


def _get_latest_sub_row(account_id: str) -> Optional[Dict[str, Any]]:
    db = supabase()
    res = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def _get_active_sub_row(account_id: str) -> Optional[Dict[str, Any]]:
    db = supabase()
    res = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", account_id)
        .eq("is_active", True)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


# -----------------------------
# Access computation
# -----------------------------
def _compute_access_state(sub_row: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    expires_at = sub_row.get("expires_at")
    is_active_flag = bool(sub_row.get("is_active"))

    if not expires_at:
        return ("active" if is_active_flag else "expired", None)

    exp_dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
    if not exp_dt:
        return ("active" if is_active_flag else "expired", expires_at)

    if is_active_flag and _now_utc() <= exp_dt:
        return ("active", expires_at)

    return ("expired", expires_at)


# -----------------------------
# Public API
# -----------------------------
def get_subscription_status(account_id: Optional[str], provider: Optional[str], provider_user_id: Optional[str]) -> Dict[str, Any]:
    aid = _find_account_id(account_id, provider, provider_user_id)
    if not aid:
        return {
            "active": False,
            "state": "none",
            "account_id": None,
            "plan_code": None,
            "expires_at": None,
            "reason": "account_not_found",
        }

    # Apply scheduled change if due (best-effort)
    try:
        apply_scheduled_change_if_due(aid)
    except Exception:
        pass

    latest = _get_latest_sub_row(aid)
    if not latest:
        return {
            "active": False,
            "state": "none",
            "account_id": aid,
            "plan_code": None,
            "expires_at": None,
            "reason": "no_subscription",
        }

    state, expires_at = _compute_access_state(latest)
    return {
        "active": state == "active",
        "state": state,
        "account_id": aid,
        "plan_code": (latest.get("plan_code") or None),
        "expires_at": expires_at,
        "reason": "ok" if state == "active" else "inactive_or_expired",
    }


# -----------------------------
# Core mutations
# -----------------------------
def _deactivate_any_active(account_id: str, reason: str = "replaced") -> None:
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return
    try:
        db.table("user_subscriptions").update(
            {"is_active": False, "status": reason, "updated_at": _iso(_now_utc())}
        ).eq("id", cur["id"]).execute()
    except Exception:
        try:
            db.table("user_subscriptions").update({"is_active": False}).eq("id", cur["id"]).execute()
        except Exception:
            pass


def _build_expiry_from_plan(plan_code: str, starts_at: datetime) -> datetime:
    plan = _get_plan(plan_code)
    duration_days = 30
    if plan:
        try:
            duration_days = int(plan.get("duration_days") or 30)
        except Exception:
            duration_days = 30
    return starts_at + timedelta(days=duration_days)


def _reset_ai_credits_best_effort(account_id: str, plan_code: str) -> None:
    try:
        init_credits_for_plan(account_id=account_id, plan_code=plan_code)
    except Exception:
        pass


def activate_subscription_now(account_id: str, plan_code: str, *, status: str = "active") -> Dict[str, Any]:
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip().lower()
    if not account_id or not plan_code:
        raise ValueError("account_id and plan_code are required")

    starts = _now_utc()
    expires = _build_expiry_from_plan(plan_code, starts)

    _deactivate_any_active(account_id, reason="replaced")

    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": status,
        "started_at": _iso(starts),
        "expires_at": _iso(expires),
        "is_active": True,
        "pending_plan_code": None,
        "pending_starts_at": None,
        "updated_at": _iso(_now_utc()),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    row = ins.data[0] if ins.data else payload

    _reset_ai_credits_best_effort(account_id, plan_code)
    return row


def schedule_plan_change_at_expiry(account_id: str, next_plan_code: str) -> Dict[str, Any]:
    account_id = (account_id or "").strip()
    next_plan_code = (next_plan_code or "").strip().lower()
    if not account_id or not next_plan_code:
        raise ValueError("account_id and next_plan_code are required")

    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return activate_subscription_now(account_id, next_plan_code, status="active")

    exp_dt = _parse_iso(cur.get("expires_at") or "") if isinstance(cur.get("expires_at"), str) else None
    if not exp_dt:
        return activate_subscription_now(account_id, next_plan_code, status="active")

    upd = (
        db.table("user_subscriptions")
        .update(
            {
                "pending_plan_code": next_plan_code,
                "pending_starts_at": _iso(exp_dt),
                "updated_at": _iso(_now_utc()),
            }
        )
        .eq("id", cur["id"])
        .execute()
    )
    return upd.data[0] if upd.data else cur


def apply_scheduled_change_if_due(account_id: str) -> Optional[Dict[str, Any]]:
    account_id = (account_id or "").strip()
    if not account_id:
        return None

    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return None

    pending_plan = (cur.get("pending_plan_code") or "").strip().lower()
    pending_starts_at = cur.get("pending_starts_at")

    if not pending_plan or not pending_starts_at:
        return None

    starts_dt = _parse_iso(pending_starts_at) if isinstance(pending_starts_at, str) else None
    if not starts_dt:
        return None

    if _now_utc() < starts_dt:
        return None

    # clear pending (best-effort)
    try:
        db.table("user_subscriptions").update(
            {"pending_plan_code": None, "pending_starts_at": None, "updated_at": _iso(_now_utc())}
        ).eq("id", cur["id"]).execute()
    except Exception:
        pass

    return activate_subscription_now(account_id, pending_plan, status="active")


# -----------------------------
# Trial
# -----------------------------
def start_trial_if_eligible(account_id: str, trial_plan_code: str = "trial") -> Dict[str, Any]:
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "account_id_required"}

    db = supabase()
    seen = (
        db.table("user_subscriptions")
        .select("id")
        .eq("account_id", account_id)
        .eq("plan_code", trial_plan_code)
        .limit(1)
        .execute()
    )
    if seen.data:
        return {"ok": False, "error": "trial_already_used"}

    sub = activate_subscription_now(account_id, trial_plan_code, status="active")
    return {"ok": True, "subscription": sub}


# -----------------------------
# Manual activation
# -----------------------------
def manual_activate_subscription(account_id: str, plan_code: Optional[str], expires_at: Optional[str]) -> Dict[str, Any]:
    account_id = (account_id or "").strip()
    plan = (plan_code or "manual").strip().lower() or "manual"
    if not account_id:
        raise ValueError("account_id is required")

    starts = _now_utc()
    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt is None:
        exp_dt = _build_expiry_from_plan(plan, starts)

    _deactivate_any_active(account_id, reason="replaced")

    payload = {
        "account_id": account_id,
        "plan_code": plan,
        "status": "active",
        "started_at": _iso(starts),
        "expires_at": _iso(exp_dt),
        "is_active": True,
        "pending_plan_code": None,
        "pending_starts_at": None,
        "updated_at": _iso(_now_utc()),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    row = ins.data[0] if ins.data else payload

    _reset_ai_credits_best_effort(account_id, plan)
    return row


# -----------------------------
# Payment success handler (Paystack webhook)
# -----------------------------
_REF_AMOUNTS_KOBO = {1: 400 * 100, 2: 200 * 100, 3: 100 * 100}


def _get_referrer_level1(referred_account_id: str) -> Optional[str]:
    db = supabase()
    try:
        r = db.table("referrals").select("referrer_id").eq("referred_id", referred_account_id).limit(1).execute()
        if r.data:
            return r.data[0].get("referrer_id")
    except Exception:
        pass
    return None


def _build_ref_chain(referred_account_id: str) -> Dict[int, Optional[str]]:
    l1 = _get_referrer_level1(referred_account_id)
    l2 = _get_referrer_level1(l1) if l1 else None
    l3 = _get_referrer_level1(l2) if l2 else None
    return {1: l1, 2: l2, 3: l3}


def _create_referral_earnings_best_effort(referred_account_id: str, plan_code: str, reference: Optional[str]) -> None:
    db = supabase()
    chain = _build_ref_chain(referred_account_id)
    now_iso = _iso(_now_utc())

    for level in (1, 2, 3):
        referrer = chain.get(level)
        if not referrer:
            continue

        row = {
            "referrer_account_id": referrer,
            "referred_account_id": referred_account_id,
            "plan_code": plan_code,
            "amount_kobo": int(_REF_AMOUNTS_KOBO[level]),
            "status": "pending",
            "created_at": now_iso,
            "reference": reference,
            "level": level,
        }

        try:
            db.table("referral_earnings").insert(row).execute()
        except Exception:
            pass


def handle_payment_success(payload: Dict[str, Any]) -> Dict[str, Any]:
    db = supabase()

    provider = (payload.get("provider") or "paystack").strip()
    reference = (payload.get("reference") or "").strip() or None
    account_id = (payload.get("account_id") or "").strip()
    plan_code = (payload.get("plan_code") or "").strip().lower()
    upgrade_mode = (payload.get("upgrade_mode") or "now").strip().lower()
    amount_kobo = int(payload.get("amount_kobo") or 0)
    currency = (payload.get("currency") or "NGN").strip().upper()
    wa_phone = (payload.get("wa_phone") or "").strip() or None
    raw = payload.get("raw")

    if not account_id or not plan_code:
        return {"ok": False, "error": "missing_account_id_or_plan_code"}

    now_iso = _iso(_now_utc())

    try:
        if reference and wa_phone:
            db.table("payments").upsert(
                {
                    "reference": reference,
                    "wa_phone": wa_phone,
                    "provider": provider,
                    "plan": plan_code,
                    "amount_kobo": amount_kobo,
                    "currency": currency,
                    "status": "success",
                    "paid_at": now_iso,
                    "updated_at": now_iso,
                    "raw": raw,
                    "email": payload.get("email"),
                    "account_id": account_id,
                    "provider_ref": payload.get("provider_ref"),
                    "plan_code": plan_code,
                },
                on_conflict="reference",
            ).execute()
    except Exception:
        pass

    if upgrade_mode == "at_expiry":
        row = schedule_plan_change_at_expiry(account_id, plan_code)
        return {"ok": True, "mode": "scheduled", "subscription": row}

    row = activate_subscription_now(account_id, plan_code, status="active")

    # Referral earnings should be created ONLY after activation (this matches your requirement)
    try:
        _create_referral_earnings_best_effort(account_id, plan_code, reference)
    except Exception:
        pass

    return {"ok": True, "mode": "activated", "subscription": row}


# -----------------------------
# Expiry maintenance (Cron job)
# -----------------------------
def expire_overdue_subscriptions(*, batch_limit: int = 1000) -> Dict[str, Any]:
    db = supabase()
    now_iso = _iso(_now_utc())

    res = (
        db.table("user_subscriptions")
        .select("id")
        .eq("is_active", True)
        .lt("expires_at", now_iso)
        .limit(int(batch_limit))
        .execute()
    )

    ids = [r.get("id") for r in (res.data or []) if r.get("id")]
    if not ids:
        return {"ok": True, "expired": 0}

    try:
        db.table("user_subscriptions").update(
            {"is_active": False, "status": "expired", "updated_at": now_iso}
        ).in_("id", ids).execute()
    except Exception:
        try:
            db.table("user_subscriptions").update({"is_active": False}).in_("id", ids).execute()
        except Exception:
            return {"ok": False, "expired": 0, "error": "update_failed"}

    return {"ok": True, "expired": len(ids)}
