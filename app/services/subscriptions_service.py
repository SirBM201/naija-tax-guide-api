from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso_z(dt: datetime) -> str:
    # Supabase accepts ISO strings; using Z is nice and consistent
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


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


# ------------------------------------------------------------
# Subscription status (Option A)
# active = is_active AND (expires_at is null OR expires_at > now)
# We do NOT rely on DB to flip expired rows automatically.
# ------------------------------------------------------------
def get_subscription_status(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Dict[str, Any]:
    """
    Expected Supabase table: public.user_subscriptions
      - id (uuid pk)
      - account_id (uuid fk -> accounts.id)
      - plan_code (text)
      - is_active (bool)
      - status (text) optional but recommended ("active"/"inactive")
      - started_at (timestamptz) optional
      - expires_at (timestamptz nullable)
      - created_at (timestamptz)
      - updated_at (timestamptz)

    HISTORY MODE:
      - many rows per account over time
      - enforce only one active row per account using a partial unique index
    """

    aid = _find_account_id(account_id, provider, provider_user_id)
    if not aid:
        return {
            "active": False,
            "account_id": None,
            "plan_code": None,
            "expires_at": None,
            "reason": "account_not_found",
        }

    db = supabase()
    # Always get the newest subscription record deterministically
    sub = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", aid)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if not sub.data:
        return {
            "active": False,
            "account_id": aid,
            "plan_code": None,
            "expires_at": None,
            "reason": "no_subscription",
        }

    row = sub.data[0]
    expires_at = row.get("expires_at")
    is_active = bool(row.get("is_active"))

    # Option A time check (authoritative for "active")
    if expires_at:
        dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
        if dt and dt <= _now_utc():
            is_active = False

    return {
        "active": is_active,
        "account_id": aid,
        "plan_code": row.get("plan_code"),
        "expires_at": expires_at,
        "reason": "ok" if is_active else "inactive_or_expired",
    }


# ------------------------------------------------------------
# Manual activation (HISTORY SAFE)
# 1) deactivate any existing active row(s)
# 2) insert a new active row
# ------------------------------------------------------------
def manual_activate_subscription(
    account_id: str,
    plan_code: Optional[str],
    expires_at: Optional[str],
) -> Dict[str, Any]:
    db = supabase()

    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt is None:
        exp_dt = _now_utc() + timedelta(days=30)

    now = _now_utc()

    # 1) deactivate any currently active subscription(s) for this account
    # (history remains; we only flip flags)
    db.table("user_subscriptions").update(
        {
            "is_active": False,
            "status": "inactive",
            "updated_at": _iso_z(now),
        }
    ).eq("account_id", account_id).eq("is_active", True).execute()

    # 2) insert a new subscription record (history row)
    payload = {
        "account_id": account_id,
        "plan_code": plan_code or "manual",
        "is_active": True,
        "status": "active",
        "started_at": _iso_z(now),
        "expires_at": _iso_z(exp_dt),
        "updated_at": _iso_z(now),
    }

    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]


# Optional helper (nice for admin/debugging)
def list_subscription_history(account_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    db = supabase()
    res = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return res.data or []
