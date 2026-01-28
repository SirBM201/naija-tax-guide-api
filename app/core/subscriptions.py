from datetime import datetime, timezone
from app.db.supabase_client import supabase

def _now():
    return datetime.now(timezone.utc)

def is_paid_active(acct_id: str) -> bool:
    r = (
        supabase()
        .table("subscriptions")
        .select("status,expires_at")
        .eq("acct_id", acct_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if not rows:
        return False

    sub = rows[0]
    if (sub.get("status") or "").strip().lower() != "active":
        return False

    exp = sub.get("expires_at")
    if not exp:
        return False

    try:
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        return exp_dt > _now()
    except Exception:
        return False
