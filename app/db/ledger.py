# app/db/ledger.py
from datetime import datetime, timezone
from typing import Tuple, Optional
from app.core.config import MONTHLY_AI_CREDITS
from app.core.utils import iso, now_utc
from app.db.supabase_client import supabase

# ai_credit_wallet: wa_phone, period_start, period_end, total_credits, used_credits, updated_at

def _month_period(dt: datetime) -> Tuple[str, str]:
    dt = dt.astimezone(timezone.utc)
    start = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    # next month
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start.date().isoformat(), end.date().isoformat()

def get_wallet(wa_phone: str) -> Optional[dict]:
    if not wa_phone:
        return None
    period_start, period_end = _month_period(now_utc())
    q = (
        supabase()
        .table("ai_credit_wallet")
        .select("*")
        .eq("wa_phone", wa_phone)
        .eq("period_start", period_start)
        .eq("period_end", period_end)
        .limit(1)
        .execute()
    )
    rows = (q.data or [])
    return rows[0] if rows else None

def ensure_wallet(wa_phone: str) -> dict:
    period_start, period_end = _month_period(now_utc())
    row = get_wallet(wa_phone)
    if row:
        return row

    now = iso(now_utc())
    supabase().table("ai_credit_wallet").insert(
        {
            "wa_phone": wa_phone,
            "period_start": period_start,
            "period_end": period_end,
            "total_credits": MONTHLY_AI_CREDITS,
            "used_credits": 0,
            "updated_at": now,
        }
    ).execute()

    return get_wallet(wa_phone) or {
        "wa_phone": wa_phone,
        "period_start": period_start,
        "period_end": period_end,
        "total_credits": MONTHLY_AI_CREDITS,
        "used_credits": 0,
    }

def remaining_credits(wa_phone: str) -> int:
    w = ensure_wallet(wa_phone)
    total = int(w.get("total_credits") or 0)
    used = int(w.get("used_credits") or 0)
    return max(total - used, 0)

def ledger_add(wa_phone: str, delta: int, reason: str = "adjustment") -> None:
    # delta is negative for spending credits
    w = ensure_wallet(wa_phone)
    now = iso(now_utc())

    used = int(w.get("used_credits") or 0)
    total = int(w.get("total_credits") or MONTHLY_AI_CREDITS)

    if delta < 0:
        used = min(used + abs(int(delta)), total)
    else:
        # if you ever add credits, reduce used
        used = max(used - int(delta), 0)

    supabase().table("ai_credit_wallet").update(
        {"used_credits": used, "updated_at": now}
    ).eq("wa_phone", w["wa_phone"]).eq("period_start", w["period_start"]).eq("period_end", w["period_end"]).execute()
