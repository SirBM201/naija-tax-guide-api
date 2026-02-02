from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _parse_iso(value: str) -> Optional[datetime]:
    try:
        # Accept "Z"
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
    """
    Expected Supabase table: user_subscriptions
      - id (uuid pk)
      - account_id (uuid fk -> accounts.id)
      - plan_code (text)
      - is_active (bool)
      - expires_at (timestamptz nullable)
      - created_at (timestamptz)
      - updated_at (timestamptz)
    Recommended unique: (account_id)
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
    sub = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", aid)
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

    # If expires exists, enforce time check
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

def manual_activate_subscription(account_id: str, plan_code: Optional[str], expires_at: Optional[str]) -> Dict[str, Any]:
    db = supabase()

    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt is None:
        exp_dt = _now_utc() + timedelta(days=30)

    payload = {
        "account_id": account_id,
        "plan_code": plan_code or "manual",
        "is_active": True,
        "expires_at": exp_dt.isoformat().replace("+00:00", "Z"),
    }

    # Upsert-like behavior: update if exists else insert
    got = (
        db.table("user_subscriptions")
        .select("id")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )

    if got.data:
        sub_id = got.data[0]["id"]
        upd = (
            db.table("user_subscriptions")
            .update(payload)
            .eq("id", sub_id)
            .execute()
        )
        return upd.data[0]

    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]
