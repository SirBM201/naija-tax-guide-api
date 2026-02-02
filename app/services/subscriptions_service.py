# app/services/subscriptions_service.py
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase


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


# -----------------------------
# Lookups
# -----------------------------
def _find_account_id(account_id: Optional[str], provider: Optional[str], provider_user_id: Optional[str]) -> Optional[str]:
    if account_id:
        return account_id

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


def _get_plan(code: str) -> Optional[Dict[str, Any]]:
    if not code:
        return None
    db = supabase()
    res = db.table("plans").select("*").eq("code", code).limit(1).execute()
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
# Access computation (active / grace / expired)
# -----------------------------
def _compute_access_state(sub_row: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Returns: (state, expires_at, grace_until)
      - state: "active" | "grace" | "expired"
    """
    expires_at = sub_row.get("expires_at")
    plan_code = sub_row.get("plan_code") or ""
    is_active_flag = bool(sub_row.get("is_active"))

    if not expires_at:
        return ("active" if is_active_flag else "expired", None, None)

    exp_dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
    if not exp_dt:
        return ("active" if is_active_flag else "expired", expires_at, None)

    plan = _get_plan(plan_code) if plan_code else None
    grace_days = int(plan.get("grace_days") or 0) if plan else 0

    now = _now_utc()
    grace_until_dt = exp_dt + timedelta(days=grace_days)

    if now <= exp_dt and is_active_flag:
        return ("active", expires_at, _iso(grace_until_dt))
    if now <= grace_until_dt and is_active_flag:
        return ("grace", expires_at, _iso(grace_until_dt))
    return ("expired", expires_at, _iso(grace_until_dt))


# -----------------------------
# Public API
# -----------------------------
def get_subscription_status(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Dict[str, Any]:
    aid = _find_account_id(account_id, provider, provider_user_id)
    if not aid:
        return {
            "active": False,
            "state": "none",
            "account_id": None,
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
            "reason": "account_not_found",
        }

    latest = _get_latest_sub_row(aid)
    if not latest:
        return {
            "active": False,
            "state": "none",
            "account_id": aid,
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
            "reason": "no_subscription",
        }

    state, expires_at, grace_until = _compute_access_state(latest)
    active = state in ("active", "grace")

    return {
        "active": active,
        "state": state,
        "account_id": aid,
        "plan_code": latest.get("plan_code"),
        "expires_at": expires_at,
        "grace_until": grace_until,
        "reason": "ok" if active else "inactive_or_expired",
    }


# -----------------------------
# Core mutations
# -----------------------------
def _deactivate_any_active(account_id: str, reason: str = "replaced") -> None:
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return

    db.table("user_subscriptions").update(
        {"is_active": False, "status": reason, "updated_at": _iso(_now_utc())}
    ).eq("id", cur["id"]).execute()


def _build_expiry_from_plan(plan_code: str, starts_at: datetime) -> datetime:
    plan = _get_plan(plan_code)
    duration_days = int(plan.get("duration_days") or 30) if plan else 30
    # If trial plan has trial_days, prefer that
    if plan and bool(plan.get("is_trial")) and plan.get("trial_days") is not None:
        duration_days = int(plan.get("trial_days") or duration_days)
    return starts_at + timedelta(days=duration_days)


def activate_subscription_now(
    account_id: str,
    plan_code: str,
    *,
    status: str = "active",
) -> Dict[str, Any]:
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
        "created_at": _iso(starts),
        "updated_at": _iso(starts),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]


def schedule_plan_change_at_expiry(account_id: str, next_plan_code: str) -> Dict[str, Any]:
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return activate_subscription_now(account_id, next_plan_code, status="active")

    expires_at = cur.get("expires_at")
    exp_dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
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
    return upd.data[0]


def apply_scheduled_change_if_due(account_id: str) -> Optional[Dict[str, Any]]:
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return None

    pending_plan = (cur.get("pending_plan_code") or "").strip()
    pending_starts_at = cur.get("pending_starts_at")

    if not pending_plan or not pending_starts_at:
        return None

    starts_dt = _parse_iso(pending_starts_at) if isinstance(pending_starts_at, str) else None
    if not starts_dt:
        return None

    if _now_utc() < starts_dt:
        return None

    # clear pending on old row
    db.table("user_subscriptions").update(
        {"pending_plan_code": None, "pending_starts_at": None, "updated_at": _iso(_now_utc())}
    ).eq("id", cur["id"]).execute()

    # activate new plan now
    return activate_subscription_now(account_id, pending_plan, status="active")


# -----------------------------
# Trial
# -----------------------------
def start_trial_if_eligible(account_id: str, trial_plan_code: str = "trial") -> Dict[str, Any]:
    """
    Simple MVP eligibility: trial once per account, inferred from subscription history.
    (No schema change required.)
    """
    db = supabase()

    # If they ever had plan_code == trial_plan_code, block
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

    sub = activate_subscription_now(account_id, trial_plan_code, status="trial")
    return {"ok": True, "subscription": sub}


# -----------------------------
# Manual activation (required by routes)
# -----------------------------
def manual_activate_subscription(account_id: str, plan_code: Optional[str], expires_at: Optional[str]) -> Dict[str, Any]:
    plan = (plan_code or "manual").strip() or "manual"
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
        "created_at": _iso(starts),
        "updated_at": _iso(starts),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]


# -----------------------------
# Webhook-ready: payment success handler
# -----------------------------
def handle_payment_success(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Idempotent-ish payment handler:
    - record event in paystack_events (if provided)
    - record payment row
    - activate subscription (or schedule if upgrade_mode='at_expiry')
    """
    db = supabase()

    event_id = (payload.get("event_id") or "").strip() or None
    provider = (payload.get("provider") or "paystack").strip()
    reference = payload.get("reference")
    account_id = (payload.get("account_id") or "").strip()
    plan_code = (payload.get("plan_code") or "").strip()
    amount_kobo = payload.get("amount_kobo")
    currency = payload.get("currency") or "NGN"
    raw = payload.get("raw")
    upgrade_mode = (payload.get("upgrade_mode") or "now").strip().lower()  # "now" | "at_expiry"

    if not account_id or not plan_code:
        return {"ok": False, "error": "missing_account_id_or_plan_code"}

    # 1) store event if table exists + event_id present
    if event_id:
        try:
            db.table("paystack_events").insert({"event_id": event_id, "payload": raw}).execute()
        except Exception:
            # ignore duplicates / table missing / etc
            pass

    # 2) store payment (best-effort; do not crash webhook)
    try:
        db.table("payments").insert(
            {
                "account_id": account_id,
                "provider": provider,
                "reference": reference,
                "amount_kobo": amount_kobo,
                "currency": currency,
                "status": "success",
                "plan_code": plan_code,
                "raw": raw,
                "created_at": _iso(_now_utc()),
                "updated_at": _iso(_now_utc()),
            }
        ).execute()
    except Exception:
        pass

    # 3) apply subscription
    if upgrade_mode == "at_expiry":
        row = schedule_plan_change_at_expiry(account_id, plan_code)
        return {"ok": True, "mode": "scheduled", "subscription": row}

    row = activate_subscription_now(account_id, plan_code, status="active")
    return {"ok": True, "mode": "activated", "subscription": row}
