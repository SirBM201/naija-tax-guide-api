import os
from datetime import date
from app.db.supabase_client import supabase
from app.core.subscriptions import is_paid_active

FREE_DAILY_ASK_LIMIT = int(os.getenv("FREE_DAILY_ASK_LIMIT", "5"))
PAID_DAILY_ASK_LIMIT = int(os.getenv("PAID_DAILY_ASK_LIMIT", "100"))

def get_daily_limit(acct_id: str) -> int:
    return PAID_DAILY_ASK_LIMIT if is_paid_active(acct_id) else FREE_DAILY_ASK_LIMIT

def increment_and_check(acct_id: str) -> tuple[bool, int, int]:
    """
    Returns:
      (allowed, used_today, limit)
    """
    d = date.today()
    limit = get_daily_limit(acct_id)

    # Read current
    r = (
        supabase()
        .table("acct_usage_daily")
        .select("ask_count")
        .eq("acct_id", acct_id)
        .eq("day", str(d))
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    used = int(rows[0]["ask_count"]) if rows else 0

    if used >= limit:
        return (False, used, limit)

    used_next = used + 1

    # Upsert new count
    supabase().table("acct_usage_daily").upsert(
        {"acct_id": acct_id, "day": str(d), "ask_count": used_next},
        on_conflict="acct_id,day"
    ).execute()

    return (True, used_next, limit)
