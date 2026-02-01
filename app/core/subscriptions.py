from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from app.db.supabase_client import supabase

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None

def is_subscription_active(row: Dict[str, Any]) -> Tuple[bool, Optional[datetime]]:
    status = (row.get("status") or "").lower()
    exp_dt = parse_dt(row.get("expires_at"))
    if status != "active":
        return False, exp_dt
    if not exp_dt:
        return False, None
    if exp_dt <= now_utc():
        return False, exp_dt
    return True, exp_dt

def get_subscription_by_acct_key(acct_key: str) -> Dict[str, Any]:
    """
    IMPORTANT: your current DB uses user_subscriptions.wa_phone to store acct:<uuid>
    (We keep that to avoid risky schema changes.)
    """
    r = (
        supabase()
        .table("user_subscriptions")
        .select("wa_phone,plan,status,expires_at,paystack_reference,updated_at")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return {"status": "none", "plan": None, "expires_at": None, "reference": None}

    row = rows[0] or {}
    active, _exp = is_subscription_active(row)
    return {
        "status": "active" if active else "expired",
        "plan": row.get("plan"),
        "expires_at": row.get("expires_at"),
        "reference": row.get("paystack_reference") or None,
    }

def require_active_subscription(acct_key: str) -> Dict[str, Any]:
    sub = get_subscription_by_acct_key(acct_key)
    if sub["status"] != "active":
        return {
            "ok": False,
            "reason": "subscription_required",
            "message": "Subscription required or expired.",
            "sub": sub,
        }
    return {"ok": True, "sub": sub}
