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
def _find_account_id(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Optional[str]:
    """
    If account_id is given -> use it.
    Else try to find account by (provider, provider_user_id) from accounts table.
    """
    if account_id:
        return account_id.strip() or None

    if not provider or not provider_user_id:
        return None

    r = (
        supabase.table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return None
    return rows[0]["id"]


def _get_plan(plan_code: str) -> Optional[Dict[str, Any]]:
    if not plan_code:
        return None

    r = (
        supabase.table("plans")
        .select("plan_code,name,duration_days,active,amount_kobo,currency")
        .eq("plan_code", plan_code)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return None
    return rows[0]


# -----------------------------
# Public: subscription status
# -----------------------------
def get_subscription_status(
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Return a normalized subscription state.
    state: none | active | grace | expired
    """
    acct = _find_account_id(account_id, provider, provider_user_id)
    if not acct:
        return {
            "account_id": None,
            "active": False,
            "expires_at": None,
            "grace_until": None,
            "plan_code": None,
            "reason": "no_account",
            "state": "none",
        }

    r = (
        supabase.table("user_subscriptions")
        .select("plan_code,active,expires_at,grace_until")
        .eq("account_id", acct)
        .order("updated_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return {
            "account_id": acct,
            "active": False,
            "expires_at": None,
            "grace_until": None,
            "plan_code": None,
            "reason": "no_subscription",
            "state": "none",
        }

    row = rows[0]
    now = _now_utc()

    expires_at = _parse_iso(row.get("expires_at") or "") if row.get("expires_at") else None
    grace_until = _parse_iso(row.get("grace_until") or "") if row.get("grace_until") else None

    active = bool(row.get("active"))
    plan_code = row.get("plan_code")

    if active and expires_at and expires_at > now:
        return {
            "account_id": acct,
            "active": True,
            "expires_at": _iso(expires_at),
            "grace_until": _iso(grace_until) if grace_until else None,
            "plan_code": plan_code,
            "reason": "active",
            "state": "active",
        }

    if grace_until and grace_until > now:
        return {
            "account_id": acct,
            "active": True,
            "expires_at": _iso(expires_at) if expires_at else None,
            "grace_until": _iso(grace_until),
            "plan_code": plan_code,
            "reason": "grace",
            "state": "grace",
        }

    return {
        "account_id": acct,
        "active": False,
        "expires_at": _iso(expires_at) if expires_at else None,
        "grace_until": _iso(grace_until) if grace_until else None,
        "plan_code": plan_code,
        "reason": "expired",
        "state": "expired",
    }


# -----------------------------
# Activation / extension helpers
# -----------------------------
def _ensure_subscription_row(account_id: str) -> Dict[str, Any]:
    """
    Ensure user_subscriptions row exists (upsert pattern).
    """
    r = (
        supabase.table("user_subscriptions")
        .select("account_id,plan_code,active,expires_at,grace_until")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return rows[0]

    row = {
        "account_id": account_id,
        "plan_code": None,
        "active": False,
        "expires_at": None,
        "grace_until": None,
    }
    supabase.table("user_subscriptions").insert(row).execute()
    return row


def _extend_from(dt: Optional[datetime], days: int) -> datetime:
    base = dt if dt and dt > _now_utc() else _now_utc()
    return base + timedelta(days=days)


def manual_activate_subscription(
    account_id: str,
    plan_code: str,
    days_override: Optional[int] = None,
    grace_days: int = 3,
) -> Dict[str, Any]:
    """
    Manually activate/extend subscription for an account.
    Used by admin tools or internal workflows.
    """
    plan = _get_plan(plan_code)
    if not plan:
        return {"ok": False, "error": f"unknown_plan:{plan_code}"}

    duration_days = int(days_override or plan.get("duration_days") or 30)
    if duration_days <= 0:
        duration_days = 30

    _ensure_subscription_row(account_id)

    # get current subscription info
    current = (
        supabase.table("user_subscriptions")
        .select("expires_at")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    rows = getattr(current, "data", None) or []
    cur_expires = _parse_iso(rows[0]["expires_at"]) if rows and rows[0].get("expires_at") else None

    new_expires = _extend_from(cur_expires, duration_days)
    grace_until = new_expires + timedelta(days=int(grace_days or 0))

    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "active": True,
        "expires_at": _iso(new_expires),
        "grace_until": _iso(grace_until),
        "updated_at": _iso(_now_utc()),
    }

    supabase.table("user_subscriptions").upsert(payload).execute()

    return {"ok": True, "account_id": account_id, "plan_code": plan_code, "expires_at": payload["expires_at"]}


# -----------------------------
# Trial helpers
# -----------------------------
def start_trial_if_eligible(account_id: str, trial_plan_code: str = "trial") -> Dict[str, Any]:
    """
    Start a trial only if:
      - account has no active subscription
      - account has never had a trial (or you can relax this later)
    """
    status = get_subscription_status(account_id=account_id)
    if status.get("state") in ("active", "grace"):
        return {"ok": True, "skipped": True, "reason": "already_active_or_grace"}

    # has trial already?
    r = (
        supabase.table("subscription_events")
        .select("id")
        .eq("account_id", account_id)
        .eq("event_type", "trial_started")
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return {"ok": True, "skipped": True, "reason": "trial_already_started_before"}

    plan = _get_plan(trial_plan_code)
    if not plan or not plan.get("active"):
        return {"ok": False, "error": f"trial_plan_not_available:{trial_plan_code}"}

    # activate trial
    out = manual_activate_subscription(
        account_id=account_id,
        plan_code=trial_plan_code,
        days_override=int(plan.get("duration_days") or 7),
        grace_days=0,
    )
    if not out.get("ok"):
        return out

    # record event
    supabase.table("subscription_events").insert(
        {
            "account_id": account_id,
            "event_type": "trial_started",
            "meta": {"plan_code": trial_plan_code},
            "created_at": _iso(_now_utc()),
        }
    ).execute()

    return {"ok": True, "started": True, "plan_code": trial_plan_code, "expires_at": out.get("expires_at")}


# -----------------------------
# Paystack webhook integration
# -----------------------------
def _find_plan_from_reference(reference: str) -> Optional[str]:
    """
    Attempt to locate plan_code from paystack reference (if you store it).
    """
    if not reference:
        return None

    r = (
        supabase.table("paystack_transactions")
        .select("plan_code")
        .eq("reference", reference)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return None
    return rows[0].get("plan_code")


def _find_account_from_reference(reference: str) -> Optional[str]:
    """
    Attempt to locate account_id from paystack reference (if you store it).
    """
    if not reference:
        return None

    r = (
        supabase.table("paystack_transactions")
        .select("account_id")
        .eq("reference", reference)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return None
    return rows[0].get("account_id")


def handle_payment_success(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Called by your webhook route when Paystack confirms payment success.
    This function should:
      - resolve account_id + plan_code
      - activate subscription
      - write a subscription_event
    """
    data = payload.get("data") or payload
    reference = data.get("reference") or data.get("ref") or ""
    metadata = data.get("metadata") or {}

    # Try metadata first
    account_id = metadata.get("account_id") or metadata.get("user_id")
    plan_code = metadata.get("plan_code") or metadata.get("plan")

    # Fallback to stored transaction lookup
    if not account_id:
        account_id = _find_account_from_reference(reference)
    if not plan_code:
        plan_code = _find_plan_from_reference(reference)

    if not account_id or not plan_code:
        return {"ok": False, "error": "missing_account_or_plan", "reference": reference}

    out = manual_activate_subscription(account_id=account_id, plan_code=plan_code)
    if not out.get("ok"):
        return out

    supabase.table("subscription_events").insert(
        {
            "account_id": account_id,
            "event_type": "payment_success",
            "meta": {
                "reference": reference,
                "plan_code": plan_code,
                "raw": {"status": data.get("status"), "amount": data.get("amount")},
            },
            "created_at": _iso(_now_utc()),
        }
    ).execute()

    return {"ok": True, "account_id": account_id, "plan_code": plan_code, "expires_at": out.get("expires_at")}


def handle_payment_failed(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Optional: called when payment fails.
    """
    data = payload.get("data") or payload
    reference = data.get("reference") or ""
    metadata = data.get("metadata") or {}
    account_id = metadata.get("account_id") or metadata.get("user_id") or _find_account_from_reference(reference)

    supabase.table("subscription_events").insert(
        {
            "account_id": account_id,
            "event_type": "payment_failed",
            "meta": {"reference": reference, "raw": {"status": data.get("status")}},
            "created_at": _iso(_now_utc()),
        }
    ).execute()

    return {"ok": True, "account_id": account_id, "reference": reference}
