from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _parse_iso(value: str) -> Optional[datetime]:
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None

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

def get_subscription_status(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Dict[str, Any]:
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

    # 1) Try to fetch CURRENT ACTIVE subscription (history mode)
    sub = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", aid)
        .eq("is_active", True)
        .order("started_at", desc=True)
        .limit(1)
        .execute()
    )

    # If none active, return no active subscription
    if not sub.data:
        # Optional: fetch latest record for context
        latest = (
            db.table("user_subscriptions")
            .select("*")
            .eq("account_id", aid)
            .order("started_at", desc=True)
            .limit(1)
            .execute()
        )
        if not latest.data:
            return {
                "active": False,
                "account_id": aid,
                "plan_code": None,
                "expires_at": None,
                "reason": "no_subscription",
            }

        row = latest.data[0]
        return {
            "active": False,
            "account_id": aid,
            "plan_code": row.get("plan_code"),
            "expires_at": row.get("expires_at"),
            "reason": "no_active_subscription",
        }

    row = sub.data[0]
    expires_at = row.get("expires_at")

    # Enforce expiry time check
    is_active = True
    if expires_at:
        dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
        if dt and dt <= _now_utc():
            is_active = False

    # If it expired but is_active still true in DB, we can treat as inactive at runtime
    return {
        "active": bool(is_active),
        "account_id": aid,
        "plan_code": row.get("plan_code"),
        "expires_at": expires_at,
        "reason": "ok" if is_active else "expired",
    }
