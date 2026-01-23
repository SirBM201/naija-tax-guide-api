# app/db/usage.py
from app.core.utils import today_utc, iso, now_utc
from app.db.supabase_client import supabase

# daily_answer_usage: wa_phone, day, total_count, last_used_at

def get_today_total(wa_phone: str) -> int:
    day = str(today_utc())
    q = (
        supabase()
        .table("daily_answer_usage")
        .select("total_count")
        .eq("wa_phone", wa_phone)
        .eq("day", day)
        .limit(1)
        .execute()
    )
    rows = (q.data or [])
    if not rows:
        return 0
    return int(rows[0].get("total_count") or 0)

def daily_total_usage_inc(wa_phone: str, inc: int = 1) -> None:
    if not wa_phone:
        return
    day = str(today_utc())
    now = iso(now_utc())

    current = get_today_total(wa_phone)
    new_total = current + int(inc or 0)

    supabase().table("daily_answer_usage").upsert(
        {
            "wa_phone": wa_phone,
            "day": day,
            "total_count": new_total,
            "last_used_at": now,
        },
        on_conflict="wa_phone,day",
    ).execute()

def ai_daily_usage_inc(wa_phone: str, total_inc: int = 1, ai_inc: int = 0) -> None:
    # You can expand later (e.g., usage_logs). For now, keep backend stable.
    # We already increment total via daily_total_usage_inc in engine.py.
    return
