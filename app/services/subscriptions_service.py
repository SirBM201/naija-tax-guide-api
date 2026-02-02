from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone
import uuid

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
def _find_account_id(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Optional[str]:
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


def _get_plan(plan_code: str) -> Optional[Dict[str, Any]]:
    """
    plans table uses:
      - code (text)   <-- IMPORTANT
      - name (text)
      - duration_days (int)
      - created_at (timestamptz)

    Optional columns (we will add via SQL):
      - price_kobo (bigint)
      - currency (text)
      - grace_days (int)
      - is_trial (bool)
      - trial_days (int)
    """
    if not plan_code:
        return None

    db = supabase()
    res = (
        db.table("plans")
        .select("*")
        .eq("code", plan_code)
        .limit(1)
        .execute()
    )
    if res.data:
        return res.data[0]
    return None


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
    if res.data:
        return res.data[0]
    return None


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
    if res.data:
        return res.data[0]
    return None


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
    grace_days = 0
    if plan is not None and isinstance(plan.get("grace_days"), int):
        grace_days = int(plan.get("grace_days") or 0)

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
    now = _iso(_now_utc())
    db.table("user_subscriptions").update(
        {"is_active": False, "status": reason, "updated_at": now}
    ).eq("account_id", account_id).eq("is_active", True).execute()


def _build_expiry_from_plan(plan_code: str, starts_at: datetime) -> datetime:
    plan = _get_plan(plan_code)

    # Default duration if plan not found
    duration_days = 30

    # Trial support: trial_days overrides duration_days when is_trial is true
    if plan:
        if bool(plan.get("is_trial")) and isinstance(plan.get("trial_days"), int):
            duration_days = int(plan.get("trial_days") or 7)
        elif isinstance(plan.get("duration_days"), int):
            duration_days = int(plan.get("duration_days") or 30)

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


# -----------------------------
# Upgrade / downgrade logic (scheduled at expiry)
# -----------------------------
def schedule_plan_change_at_expiry(account_id: str, next_plan_code: str) -> Dict[str, Any]:
    """
    Stores pending plan change on the current active row.
    Requires SQL columns on user_subscriptions:
      - pending_plan_code text
      - pending_starts_at timestamptz
    """
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return activate_subscription_now(account_id, next_plan_code, status="active")

    exp = cur.get("expires_at")
    exp_dt = _parse_iso(exp) if isinstance(exp, str) else None
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
    """
    You can call this cheaply from /api/ask before checking access.
    Later you can move it to a cron job.
    """
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

    return activate_subscription_now(account_id, pending_plan, status="active")


# -----------------------------
# Trial
# -----------------------------
def start_trial_if_eligible(account_id: str, trial_plan_code: str = "trial") -> Dict[str, Any]:
    """
    Simple trial rule:
      - accounts.has_used_trial boolean (SQL below)
      - if already used -> block
      - else activate trial and mark used
    """
    db = supabase()
    acc = db.table("accounts").select("id, has_used_trial").eq("id", account_id).limit(1).execute()
    if not acc.data:
        return {"ok": False, "error": "account_not_found"}

    used = bool(acc.data[0].get("has_used_trial"))
    if used:
        return {"ok": False, "error": "trial_already_used"}

    sub = activate_subscription_now(account_id, trial_plan_code, status="trial")
    db.table("accounts").update({"has_used_trial": True}).eq("id", account_id).execute()

    return {"ok": True, "subscription": sub}


# -----------------------------
# Route-compatible manual activation (required by app/routes/subscriptions.py)
# -----------------------------
def manual_activate_subscription(account_id: str, plan_code: Optional[str], expires_at: Optional[str]) -> Dict[str, Any]:
    """
    Used by POST /subscription/activate (admin-only).
    Creates a NEW subscription row and deactivates any previous active row.
    """
    plan = (plan_code or "monthly").strip() or "monthly"
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
# Webhook-ready payment success handler (required by app/routes/webhooks.py)
# -----------------------------
def handle_payment_success(
    *,
    account_id: str,
    plan_code: str,
    paid_at: Optional[str] = None,
    reference: Optional[str] = None,
    amount_kobo: Optional[int] = None,
    currency: Optional[str] = None,
    provider: str = "paystack",
    raw_event: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Called by webhook route after verifying signature.

    Behavior:
    - deactivates any active subscription
    - inserts a NEW active subscription row
    - (optional) logs payment in payments table if it exists
    """
    if not account_id:
        raise ValueError("account_id is required")
    if not plan_code:
        raise ValueError("plan_code is required")

    started = _parse_iso(paid_at) if paid_at else None
    if started is None:
        started = _now_utc()

    expires = _build_expiry_from_plan(plan_code, started)

    _deactivate_any_active(account_id, reason="replaced")

    sub_payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": "active",
        "started_at": _iso(started),
        "expires_at": _iso(expires),
        "is_active": True,
        "created_at": _iso(_now_utc()),
        "updated_at": _iso(_now_utc()),
    }

    db = supabase()
    sub_ins = db.table("user_subscriptions").insert(sub_payload).execute()
    sub_row = sub_ins.data[0]

    # Optional: save payment record (doesn't break boot if payments table missing)
    try:
        pay_payload = {
            "account_id": account_id,
            "provider": provider,
            "reference": reference or str(uuid.uuid4()),
            "amount_kobo": amount_kobo,
            "currency": currency or "NGN",
            "status": "success",
            "paid_at": _iso(started),
            "created_at": _iso(_now_utc()),
            "raw_event": raw_event,
        }
        db.table("payments").insert(pay_payload).execute()
    except Exception:
        pass

    return {"ok": True, "subscription": sub_row}
