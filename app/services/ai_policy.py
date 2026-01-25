# app/services/ai_policy.py
import logging
from datetime import datetime, timezone, date
from typing import Dict, Any, Optional

FREE_DAILY_LIMIT = 2

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


def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


def _get_subscription(identity: str) -> Optional[Dict[str, Any]]:
    try:
        r = _db().table("user_subscriptions").select("*").eq("wa_phone", identity).limit(1).execute()
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
    return PAID_MONTHLY_CREDITS


def _get_daily_usage(identity: str) -> Dict[str, Any]:
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


def _ensure_paid_ledger(identity: str, sub: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure ai_credit_ledger exists for this subscription period_end=expires_at
    with base credits for plan (rollover valid for plan period).
    """
    period_end = str(sub.get("expires_at"))
    plan = sub.get("plan") or "paid"
    base = _paid_quota_for_plan(plan)

    try:
        r = (
            _db()
            .table("ai_credit_ledger")
            .select("*")
            .eq("wa_phone", identity)
            .eq("period_end", period_end)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        if rows:
            return rows[0]
    except Exception:
        pass

    # Create ledger row if missing
    try:
        _db().table("ai_credit_ledger").upsert(
            {
                "wa_phone": identity,
                "period_end": period_end,
                "plan": plan,
                "credits_total": base,
                "credits_used": 0,
                "updated_at": _iso_now(),
            },
            on_conflict="wa_phone,period_end",
        ).execute()

        r2 = (
            _db()
            .table("ai_credit_ledger")
            .select("*")
            .eq("wa_phone", identity)
            .eq("period_end", period_end)
            .limit(1)
            .execute()
        )
        rows2 = getattr(r2, "data", None) or []
        return rows2[0] if rows2 else {"credits_total": base, "credits_used": 0, "period_end": period_end}
    except Exception as e:
        logging.exception("ensure paid ledger failed: %s", e)
        return {"credits_total": base, "credits_used": 0, "period_end": period_end}


def can_use_ai(identity: str) -> Dict[str, Any]:
    identity = _normalize_phone(identity)
    if not identity:
        return {"ok": False, "reason": "missing_identity", "action": "upgrade"}

    sub = _get_subscription(identity)
    if sub and _is_active_paid(sub):
        ledger = _ensure_paid_ledger(identity, sub)
        total = int(ledger.get("credits_total") or 0)
        used = int(ledger.get("credits_used") or 0)
        remaining = total - used

        if remaining <= 0:
            return {"ok": False, "reason": "paid_credits_exhausted", "action": "topup"}

        return {
            "ok": True,
            "plan": sub.get("plan") or "paid",
            "mode": "paid_credits",
            "period_end": str(sub.get("expires_at")),
            "remaining": remaining,
        }

    # Free daily limit
    row = _get_daily_usage(identity)
    used = int(row.get("count") or 0)
    if used >= FREE_DAILY_LIMIT:
        return {"ok": False, "reason": "free_daily_limit_reached", "action": "upgrade"}

    return {"ok": True, "plan": "free", "mode": "free_daily"}


def consume_ai(identity: str, plan: str, mode: str, period_end: Optional[str] = None) -> None:
    identity = _normalize_phone(identity)
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

    if mode == "paid_credits":
        # Need period_end from subscription to increment correct ledger row
        if not period_end:
            sub = _get_subscription(identity) or {}
            period_end = str(sub.get("expires_at") or "")

        if not period_end:
            return

        try:
            r = (
                _db()
                .table("ai_credit_ledger")
                .select("credits_total,credits_used")
                .eq("wa_phone", identity)
                .eq("period_end", period_end)
                .limit(1)
                .execute()
            )
            rows = getattr(r, "data", None) or []
            row = rows[0] if rows else {"credits_total": _paid_quota_for_plan(plan), "credits_used": 0}
            used = int(row.get("credits_used") or 0) + 1
            total = int(row.get("credits_total") or 0)

            _db().table("ai_credit_ledger").upsert(
                {
                    "wa_phone": identity,
                    "period_end": period_end,
                    "plan": plan or "paid",
                    "credits_total": total,
                    "credits_used": used,
                    "updated_at": _iso_now(),
                },
                on_conflict="wa_phone,period_end",
            ).execute()
        except Exception as e:
            logging.exception("paid credit consume failed: %s", e)
        return


def log_ai_cost(identity: str, question: str, answer: str, source: str = "ai") -> None:
    # Best-effort analytics (doesn't break flow)
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
        return
