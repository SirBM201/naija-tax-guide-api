# app/services/ai_policy.py
import logging
from datetime import datetime, timezone, date
from typing import Dict, Any, Optional

FREE_DAILY_LIMIT = 2

# Paid plan quotas (agreed)
PAID_MONTHLY_CREDITS = 300
PAID_QUARTERLY_CREDITS = 900
PAID_YEARLY_CREDITS = 3600


def _db():
    from app.db.supabase_client import supabase as get_supabase
    return get_supabase()


def _utc_today() -> date:
    return datetime.now(timezone.utc).date()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_subscription(identity: str) -> Optional[Dict[str, Any]]:
    """
    user_subscriptions table uses wa_phone as key (from your screenshots).
    """
    try:
        r = (
            _db()
            .table("user_subscriptions")
            .select("*")
            .eq("wa_phone", identity)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None


def _is_active_paid(sub: Dict[str, Any]) -> bool:
    if not sub:
        return False

    status = (sub.get("status") or "").lower()
    if status and status not in ("active", "paid"):
        return False

    exp = sub.get("expires_at")
    if not exp:
        return False

    try:
        # expires_at is timestamptz; compare in UTC
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        return exp_dt > datetime.now(timezone.utc)
    except Exception:
        return False


def _paid_quota_for_plan(plan: str) -> int:
    p = (plan or "").lower().strip()
    if p in ("monthly", "month"):
        return PAID_MONTHLY_CREDITS
    if p in ("quarterly", "quarter", "3months", "3_months"):
        return PAID_QUARTERLY_CREDITS
    if p in ("yearly", "annual", "year"):
        return PAID_YEARLY_CREDITS
    # default paid quota if unknown paid plan
    return PAID_MONTHLY_CREDITS


def _get_daily_usage(identity: str) -> Dict[str, Any]:
    """
    ai_daily_usage: wa_phone (text), day (date), count (int), last_used_at (timestamptz)
    Screenshot also shows ai_count, but we won't rely on it unless you confirm.
    """
    today = _utc_today().isoformat()
    try:
        r = (
            _db()
            .table("ai_daily_usage")
            .select("*")
            .eq("wa_phone", identity)
            .eq("day", today)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else {"wa_phone": identity, "day": today, "count": 0}
    except Exception as e:
        logging.exception("ai_daily_usage read failed: %s", e)
        return {"wa_phone": identity, "day": today, "count": 0}


def can_use_ai(identity: str) -> Dict[str, Any]:
    """
    Returns:
      { ok: True, plan: "free"|..., mode: "free_daily"|"paid_credits" }
      OR { ok: False, reason: "...", action: "upgrade"|"topup" }
    """
    identity = (identity or "").strip()
    if not identity:
        return {"ok": False, "reason": "missing_identity", "action": "upgrade"}

    sub = _get_subscription(identity)
    if sub and _is_active_paid(sub):
        # Paid users: allow AI; credit exhaustion enforcement will be added at top-up stage.
        # For now, allow and let consume_ai maintain counters if you add them later.
        return {"ok": True, "plan": sub.get("plan") or "paid", "mode": "paid_credits"}

    # Free daily limit
    row = _get_daily_usage(identity)
    used = int(row.get("count") or 0)
    if used >= FREE_DAILY_LIMIT:
        return {"ok": False, "reason": "free_daily_limit_reached", "action": "upgrade"}

    return {"ok": True, "plan": "free", "mode": "free_daily"}


def consume_ai(identity: str, plan: str, mode: str) -> None:
    """
    Free users: increment ai_daily_usage.count
    Paid users: currently no hard monthly decrement table enforced in this file
              (we will implement paid credit decrement in the Top-up stage).
    """
    identity = (identity or "").strip()
    if not identity:
        return

    if mode == "free_daily":
        today = _utc_today().isoformat()
        row = _get_daily_usage(identity)
        used = int(row.get("count") or 0) + 1

        try:
            _db().table("ai_daily_usage").upsert(
                {
                    "wa_phone": identity,
                    "day": today,
                    "count": used,
                    "last_used_at": _iso_now(),
                },
                on_conflict="wa_phone,day",
            ).execute()
        except Exception as e:
            logging.exception("ai_daily_usage upsert failed: %s", e)
        return

    # paid_credits mode (placeholder now; full credit ledger will be implemented in Top-up step)
    return


def log_ai_cost(identity: str, question: str, answer: str, source: str = "ai") -> None:
    """
    Optional analytics. Best-effort.
    If your ai_cost table differs, this will not break the app.
    """
    try:
        _db().table("ai_cache").insert(
            {
                "wa_phone": (identity or "")[:40],
                "question": (question or "")[:500],
                "answer": (answer or "")[:4000],
                "source": (source or "")[:30],
                "created_at": _iso_now(),
            }
        ).execute()
    except Exception:
        # ignore: analytics shouldn't break user flow
        return
