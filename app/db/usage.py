# app/db/usage.py
from app.db.supabase_client import get_supabase
from app.core.utils import today_utc, iso, now_utc

def daily_total_usage_inc(wa_phone: str, inc: int = 1) -> None:
    sb = get_supabase()
    d = str(today_utc())
    sb.table("daily_answer_usage").upsert(
        {"wa_phone": wa_phone, "day": d, "count": inc, "updated_at": iso(now_utc())},
        on_conflict="wa_phone,day"
    ).execute()

def ai_daily_usage_inc(wa_phone: str, total_inc: int = 1, ai_inc: int = 0) -> None:
    sb = get_supabase()
    d = str(today_utc())
    sb.table("ai_daily_usage").upsert(
        {"wa_phone": wa_phone, "day": d, "total": total_inc, "ai": ai_inc, "updated_at": iso(now_utc())},
        on_conflict="wa_phone,day"
    ).execute()
