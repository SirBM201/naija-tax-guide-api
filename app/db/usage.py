# app/db/usage.py
from __future__ import annotations

import logging
from datetime import date
from typing import Optional

from supabase import create_client

from app.core.config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
from app.core.utils import today_utc, iso_date, now_utc, iso


_sb = None


def _client():
    global _sb
    if _sb is not None:
        return _sb
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Supabase ENV not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).")
    _sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _sb


def daily_total_get(wa_phone: str, day: Optional[str] = None) -> int:
    """
    Returns today's total_count from daily_answer_usage.
    day format: 'YYYY-MM-DD' (optional). Defaults to today UTC.
    """
    if not wa_phone:
        return 0
    sb = _client()
    day = (day or iso_date(today_utc())).strip()

    try:
        r = (
            sb.table("daily_answer_usage")
            .select("total_count")
            .eq("wa_phone", wa_phone)
            .eq("day", day)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        if not rows:
            return 0
        v = rows[0].get("total_count")
        return int(v or 0)
    except Exception:
        logging.exception("daily_total_get failed")
        return 0


def daily_total_usage_inc(wa_phone: str, inc: int = 1) -> None:
    """
    Increments daily_answer_usage.total_count for today.
    """
    if not wa_phone:
        return
    sb = _client()
    day = iso_date(today_utc())

    try:
        # get current
        current = daily_total_get(wa_phone, day=day)
        new_val = current + int(inc or 0)

        sb.table("daily_answer_usage").upsert(
            {
                "wa_phone": wa_phone,
                "day": day,
                "total_count": new_val,
                "updated_at": iso(now_utc()),
            },
            on_conflict="wa_phone,day",
        ).execute()
    except Exception:
        logging.exception("daily_total_usage_inc failed")


def ai_daily_usage_inc(wa_phone: str, total_inc: int = 1, ai_inc: int = 0) -> None:
    """
    Tracks overall daily usage and how many were AI.
    Table: ai_daily_usage (wa_phone, day, count, ai_count)
    """
    if not wa_phone:
        return
    sb = _client()
    day = iso_date(today_utc())

    try:
        # read current
        r = (
            sb.table("ai_daily_usage")
            .select("count,ai_count")
            .eq("wa_phone", wa_phone)
            .eq("day", day)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        cur_count = int((rows[0].get("count") if rows else 0) or 0)
        cur_ai = int((rows[0].get("ai_count") if rows else 0) or 0)

        new_count = cur_count + int(total_inc or 0)
        new_ai = cur_ai + int(ai_inc or 0)

        sb.table("ai_daily_usage").upsert(
            {
                "wa_phone": wa_phone,
                "day": day,
                "count": new_count,
                "ai_count": new_ai,
                "updated_at": iso(now_utc()),
            },
            on_conflict="wa_phone,day",
        ).execute()
    except Exception:
        logging.exception("ai_daily_usage_inc failed")
