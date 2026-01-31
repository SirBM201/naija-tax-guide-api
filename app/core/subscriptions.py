# app/core/subscriptions.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

from app.core.supabase_client import supabase


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        # handles "2026-01-31T00:00:00+00:00" or "...Z"
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def is_subscription_active(row: Dict[str, Any]) -> Tuple[bool, Optional[datetime]]:
    """
    Returns (active?, expiry_dt)
    """
    status = (row.get("status") or "").lower()
    exp_raw = row.get("expires_at")
    exp_dt = parse_dt(exp_raw)

    if status != "active":
        return False, exp_dt

    if not exp_dt:
        return False, None

    if exp_dt <= now_utc():
        return False, exp_dt

    return True, exp_dt


def get_subscription_by_acct_key(acct_key: str) -> Dict[str, Any]:
    """
    user_subscriptions table uses wa_phone to store acct_key.
    """
    r = (
        supabase()
        .table("user_subscriptions")
        .select("wa_phone,plan,status,expires_at,paystack_reference,updated_at")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )
    if not r.data:
        return {"status": "none", "plan": None, "expires_at": None, "reference": None}

    row = r.data[0]
    active, exp_dt = is_subscription_active(row)

    return {
        "status": "active" if active else "expired",
        "plan": row.get("plan"),
        "expires_at": row.get("expires_at"),
        "reference": row.get("paystack_reference") or None,
    }


def require_active_subscription(acct_key: str) -> Dict[str, Any]:
    """
    Returns dict with:
      {ok: True, sub: {...}} or {ok: False, reason: "...", sub: {...}}
    """
    sub = get_subscription_by_acct_key(acct_key)
    if sub["status"] != "active":
        return {
            "ok": False,
            "reason": "subscription_required",
            "message": "Subscription inactive or expired. Please subscribe to continue.",
            "sub": sub,
        }

    return {"ok": True, "sub": sub}
