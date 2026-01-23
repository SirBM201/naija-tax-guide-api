# app/db/usage.py
from typing import Dict, Any
from app.core.utils import today_utc, iso_date
from app.db.supabase_rest import sb_get, sb_post, sb_patch


def get_daily_total_count(wa_phone: str) -> int:
    day = iso_date(today_utc())
    rows = sb_get(
        "daily_answer_usage",
        params={
            "select": "total_count",
            "wa_phone": f"eq.{wa_phone}",
            "day": f"eq.{day}",
            "limit": "1",
        },
    )
    if not rows:
        return 0
    return int(rows[0].get("total_count") or 0)


def daily_total_usage_inc(wa_phone: str, inc: int = 1) -> None:
    day = iso_date(today_utc())

    rows = sb_get(
        "daily_answer_usage",
        params={
            "select": "wa_phone,day,total_count",
            "wa_phone": f"eq.{wa_phone}",
            "day": f"eq.{day}",
            "limit": "1",
        },
    )

    if not rows:
        sb_post("daily_answer_usage", {"wa_phone": wa_phone, "day": day, "total_count": inc})
        return

    current = int(rows[0].get("total_count") or 0)
    sb_patch(
        "daily_answer_usage",
        {"total_count": current + inc},
        params={"wa_phone": f"eq.{wa_phone}", "day": f"eq.{day}"},
    )


def ai_daily_usage_inc(wa_phone: str, total_inc: int = 0, ai_inc: int = 0) -> None:
    day = iso_date(today_utc())

    rows = sb_get(
        "ai_daily_usage",
        params={
            "select": "wa_phone,day,count,ai_count",
            "wa_phone": f"eq.{wa_phone}",
            "day": f"eq.{day}",
            "limit": "1",
        },
    )

    if not rows:
        sb_post("ai_daily_usage", {"wa_phone": wa_phone, "day": day, "count": total_inc, "ai_count": ai_inc})
        return

    current_total = int(rows[0].get("count") or 0)
    current_ai = int(rows[0].get("ai_count") or 0)
    sb_patch(
        "ai_daily_usage",
        {"count": current_total + total_inc, "ai_count": current_ai + ai_inc},
        params={"wa_phone": f"eq.{wa_phone}", "day": f"eq.{day}"},
    )
