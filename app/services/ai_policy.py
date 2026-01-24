import os
import logging
from datetime import date, datetime, timezone
from typing import Dict, Any, Optional, Tuple

from app.db.supabase_client import supabase  # IMPORTANT: must exist in your project


FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_AI_LIMIT", "2"))
PAID_MONTHLY_LIMIT = int(os.getenv("PAID_MONTHLY_AI_LIMIT", "300"))

# Estimated token/cost tracking (simple + stable)
# You can refine later if you want exact token usage.
DEFAULT_AI_COST_UNITS = float(os.getenv("AI_COST_UNITS_PER_ANSWER", "1.0"))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _today_utc() -> date:
    return _utc_now().date()


def _plan_ai_allowance(plan: str) -> int:
    """
    300 per month.
    Quarterly/yearly roll over within validity:
    - quarterly => 900
    - yearly    => 3600
    """
    p = (plan or "").lower().strip()
    if p == "quarterly":
        return PAID_MONTHLY_LIMIT * 3
    if p == "yearly":
        return PAID_MONTHLY_LIMIT * 12
    if p == "monthly":
        return PAID_MONTHLY_LIMIT
    return 0


def get_user_plan(wa_phone: str) -> Tuple[str, Optional[str]]:
    """
    Returns (plan, expires_at_iso or None)
    Uses table: user_subscriptions (wa_phone, plan, status, expires_at)
    """
    try:
        r = (
            supabase.table("user_subscriptions")
            .select("plan,status,expires_at")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = r.data or []
        if not rows:
            return ("free", None)

        row = rows[0]
        status = (row.get("status") or "").lower()
        plan = (row.get("plan") or "free").lower()
        expires_at = row.get("expires_at")

        if status != "active":
            return ("free", expires_at)

        # If expired, treat as free
        if expires_at:
            try:
                exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if exp <= _utc_now():
                    return ("free", expires_at)
            except Exception:
                pass

        return (plan, expires_at)
    except Exception as e:
        logging.exception("get_user_plan failed: %s", e)
        return ("free", None)


def _get_or_init_ai_credits(wa_phone: str, plan: str, expires_at: Optional[str]) -> Dict[str, Any]:
    """
    Table: ai_credits
    expected columns (best effort):
      - wa_phone (pk/unique)
      - plan
      - remaining
      - expires_at
      - updated_at
    """
    allowance = _plan_ai_allowance(plan)

    try:
        r = (
            supabase.table("ai_credits")
            .select("wa_phone,plan,remaining,expires_at")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = r.data or []
        if rows:
            return rows[0]
    except Exception as e:
        logging.exception("ai_credits select failed: %s", e)

    # init if missing (only for paid plans)
    row = {
        "wa_phone": wa_phone,
        "plan": plan,
        "remaining": allowance,
        "expires_at": expires_at,
        "updated_at": _utc_now().isoformat(),
    }
    try:
        supabase.table("ai_credits").upsert(row, on_conflict="wa_phone").execute()
    except Exception as e:
        logging.exception("ai_credits upsert(init) failed: %s", e)
    return row


def can_use_ai(wa_phone: str) -> Dict[str, Any]:
    """
    Returns:
      { ok: True, plan: ..., mode: "free_daily"|"paid_credits", remaining: int }
    or:
      { ok: False, reason: "...", action: "upgrade"|"topup" }
    """
    plan, expires_at = get_user_plan(wa_phone)

    # FREE
    if plan == "free":
        today = str(_today_utc())
        try:
            r = (
                supabase.table("ai_daily_usage")
                .select("count")
                .eq("wa_phone", wa_phone)
                .eq("day", today)
                .limit(1)
                .execute()
            )
            rows = r.data or []
            used = int(rows[0].get("count") or 0) if rows else 0
        except Exception as e:
            logging.exception("ai_daily_usage read failed: %s", e)
            used = 0

        remaining = max(0, FREE_DAILY_LIMIT - used)
        if remaining <= 0:
            return {"ok": False, "reason": "free_daily_exhausted", "action": "upgrade"}

        return {"ok": True, "plan": "free", "mode": "free_daily", "remaining": remaining}

    # PAID
    allowance = _plan_ai_allowance(plan)
    if allowance <= 0:
        # unknown plan -> treat as free behavior
        return {"ok": False, "reason": "plan_unknown", "action": "upgrade"}

    credits = _get_or_init_ai_credits(wa_phone, plan, expires_at)
    remaining = int(credits.get("remaining") or 0)

    if remaining <= 0:
        return {"ok": False, "reason": "paid_credits_exhausted", "action": "topup"}

    return {"ok": True, "plan": plan, "mode": "paid_credits", "remaining": remaining, "expires_at": expires_at}


def consume_ai(wa_phone: str, plan: str, mode: str) -> None:
    """
    Deduct 1 AI usage from either:
    - ai_daily_usage (free)
    - ai_credits (paid)
    """
    if mode == "free_daily":
        today = str(_today_utc())
        try:
            # Upsert-increment pattern
            r = (
                supabase.table("ai_daily_usage")
                .select("count")
                .eq("wa_phone", wa_phone)
                .eq("day", today)
                .limit(1)
                .execute()
            )
            rows = r.data or []
            if rows:
                new_count = int(rows[0].get("count") or 0) + 1
                supabase.table("ai_daily_usage").update({"count": new_count}).eq("wa_phone", wa_phone).eq("day", today).execute()
            else:
                supabase.table("ai_daily_usage").insert({"wa_phone": wa_phone, "day": today, "count": 1}).execute()
        except Exception as e:
            logging.exception("consume_ai free_daily failed: %s", e)
        return

    # paid credits
    try:
        credits = _get_or_init_ai_credits(wa_phone, plan, None)
        remaining = int(credits.get("remaining") or 0)
        remaining = max(0, remaining - 1)
        supabase.table("ai_credits").upsert(
            {
                "wa_phone": wa_phone,
                "plan": plan,
                "remaining": remaining,
                "updated_at": _utc_now().isoformat(),
            },
            on_conflict="wa_phone",
        ).execute()
    except Exception as e:
        logging.exception("consume_ai paid_credits failed: %s", e)


def log_ai_cost(wa_phone: str, question: str, answer: str, source: str = "ai") -> None:
    """
    Lightweight cost tracking.
    Table available in your DB: ai_cache (we log a row).
    If columns differ, failure is ignored (won’t break user responses).
    """
    try:
        supabase.table("ai_cache").insert(
            {
                "wa_phone": wa_phone,
                "question": (question or "")[:500],
                "answer": (answer or "")[:1500],
                "source": source,
                "cost_units": DEFAULT_AI_COST_UNITS,
                "created_at": _utc_now().isoformat(),
            }
        ).execute()
    except Exception as e:
        logging.exception("log_ai_cost failed (ignored): %s", e)
