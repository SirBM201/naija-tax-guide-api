import logging
from datetime import datetime, timezone, date
from typing import Any, Dict, Optional


# -----------------------------
# Time helpers
# -----------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def today_utc() -> date:
    return now_utc().date()


def first_day_of_month(d: date) -> date:
    return date(d.year, d.month, 1)


def first_day_of_quarter(d: date) -> date:
    q = (d.month - 1) // 3  # 0..3
    month = q * 3 + 1
    return date(d.year, month, 1)


def first_day_of_year(d: date) -> date:
    return date(d.year, 1, 1)


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        s = str(value)
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


# -----------------------------
# DB
# -----------------------------
def _db():
    from app.db.supabase_client import supabase as get_supabase
    return get_supabase()


def _safe_first(res: Any) -> Optional[Dict[str, Any]]:
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


# -----------------------------
# Policy (FINAL & AGREED)
# -----------------------------
PLAN_FREE = "free"
PLAN_MONTHLY = "monthly"
PLAN_QUARTERLY = "quarterly"
PLAN_YEARLY = "yearly"

FREE_DAILY_LIMIT = 2

CREDITS_BY_PLAN = {
    PLAN_MONTHLY: 300,
    PLAN_QUARTERLY: 900,
    PLAN_YEARLY: 3600,
}


def _normalize_plan(plan: str) -> str:
    p = (plan or "").lower().strip()
    if p in (PLAN_MONTHLY, PLAN_QUARTERLY, PLAN_YEARLY):
        return p
    return PLAN_FREE


def _plan_period_start(plan: str, d: date) -> date:
    """
    Your ai_credits table has a 'month' date column.
    We'll store the plan period "anchor" in this column.

    - monthly: first day of this month
    - quarterly: first day of this quarter
    - yearly: Jan 1
    """
    p = _normalize_plan(plan)
    if p == PLAN_MONTHLY:
        return first_day_of_month(d)
    if p == PLAN_QUARTERLY:
        return first_day_of_quarter(d)
    if p == PLAN_YEARLY:
        return first_day_of_year(d)
    return first_day_of_month(d)


# -----------------------------
# Subscription reader
# -----------------------------
def _get_active_subscription(wa_phone: str) -> Dict[str, Any]:
    """
    Best-effort read from user_subscriptions.

    Expected (common) columns:
      - wa_phone
      - plan
      - status
      - expires_at
      - user_id (uuid)  <-- IMPORTANT for ai_credits
      - created_at / updated_at (optional)

    Returns:
      {
        "active": bool,
        "plan": "free|monthly|quarterly|yearly",
        "expires_at": datetime|None,
        "plan_expiry": str|None,
        "user_id": str|None
      }
    """
    wa = (wa_phone or "").strip()
    if not wa:
        return {"active": False, "plan": PLAN_FREE, "expires_at": None, "plan_expiry": None, "user_id": None}

    try:
        res = (
            _db()
            .table("user_subscriptions")
            .select("plan,status,expires_at,user_id,created_at,updated_at")
            .eq("wa_phone", wa)
            .limit(1)
            .execute()
        )
        row = _safe_first(res)
        if not row:
            return {"active": False, "plan": PLAN_FREE, "expires_at": None, "plan_expiry": None, "user_id": None}

        plan = _normalize_plan(row.get("plan") or PLAN_FREE)
        status = (row.get("status") or "").lower().strip()
        exp_dt = _parse_dt(row.get("expires_at"))
        user_id = row.get("user_id")

        active = bool(status == "active" and exp_dt and exp_dt > now_utc() and plan != PLAN_FREE)
        plan_expiry = iso(exp_dt) if exp_dt else None

        return {
            "active": active,
            "plan": plan if active else PLAN_FREE,
            "expires_at": exp_dt,
            "plan_expiry": plan_expiry,
            "user_id": str(user_id) if user_id else None,
        }

    except Exception as e:
        logging.exception("user_subscriptions read failed (fallback free): %s", e)
        return {"active": False, "plan": PLAN_FREE, "expires_at": None, "plan_expiry": None, "user_id": None}


# -----------------------------
# Free daily usage (ai_daily_usage)
# -----------------------------
def _get_free_daily_count(wa_phone: str) -> int:
    wa = (wa_phone or "").strip()
    if not wa:
        return 0
    d = str(today_utc())

    try:
        res = (
            _db()
            .table("ai_daily_usage")
            .select("count")
            .eq("wa_phone", wa)
            .eq("day", d)
            .limit(1)
            .execute()
        )
        row = _safe_first(res)
        if not row:
            return 0
        try:
            return int(row.get("count") or 0)
        except Exception:
            return 0
    except Exception as e:
        logging.exception("ai_daily_usage read failed: %s", e)
        return 0


def _inc_free_daily_count(wa_phone: str) -> None:
    wa = (wa_phone or "").strip()
    if not wa:
        return

    d = str(today_utc())
    current = _get_free_daily_count(wa)
    new_val = current + 1

    # Best-effort upsert on (wa_phone, day). If no unique constraint exists,
    # fallback to update then insert.
    try:
        _db().table("ai_daily_usage").upsert(
            {
                "wa_phone": wa,
                "day": d,
                "count": new_val,
                "last_used_at": iso(now_utc()),
            },
            on_conflict="wa_phone,day",
        ).execute()
        return
    except Exception:
        pass

    # Update then insert fallback
    try:
        _db().table("ai_daily_usage").update(
            {"count": new_val, "last_used_at": iso(now_utc())}
        ).eq("wa_phone", wa).eq("day", d).execute()
        return
    except Exception:
        pass

    try:
        _db().table("ai_daily_usage").insert(
            {"wa_phone": wa, "day": d, "count": new_val, "last_used_at": iso(now_utc())}
        ).execute()
    except Exception as e:
        logging.exception("ai_daily_usage increment failed (ignored): %s", e)


# -----------------------------
# Paid credits (ai_credits)
# -----------------------------
def _get_or_create_credit_row(user_id: str, plan: str) -> Dict[str, Any]:
    """
    ai_credits schema (from your screenshot):
      user_id (uuid), plan (text), month (date),
      credits_total, credits_used, credits_available

    We store one row per user per plan period anchor (month field).

    Returns:
      { ok: bool, credits_available: int, credits_used: int, credits_total: int, month: str }
    """
    uid = (user_id or "").strip()
    if not uid:
        return {"ok": False, "credits_available": 0, "credits_used": 0, "credits_total": 0, "month": None}

    p = _normalize_plan(plan)
    if p == PLAN_FREE:
        return {"ok": False, "credits_available": 0, "credits_used": 0, "credits_total": 0, "month": None}

    anchor = _plan_period_start(p, today_utc())
    anchor_s = str(anchor)

    # Try read current period
    try:
        res = (
            _db()
            .table("ai_credits")
            .select("user_id,plan,month,credits_total,credits_used,credits_available")
            .eq("user_id", uid)
            .eq("month", anchor_s)
            .limit(1)
            .execute()
        )
        row = _safe_first(res)
        if row:
            total = int(row.get("credits_total") or 0)
            used = int(row.get("credits_used") or 0)
            avail = row.get("credits_available")
            avail_int = int(avail) if avail is not None else max(0, total - used)
            return {"ok": True, "credits_total": total, "credits_used": used, "credits_available": avail_int, "month": anchor_s}
    except Exception as e:
        logging.exception("ai_credits read failed: %s", e)

    # Create new period row
    total = int(CREDITS_BY_PLAN.get(p, 300))
    used = 0
    avail = total

    payload = {
        "user_id": uid,
        "plan": p,
        "month": anchor_s,
        "credits_total": total,
        "credits_used": used,
        "credits_available": avail,
    }

    # Best-effort upsert; if unique constraint differs, fallback insert.
    try:
        _db().table("ai_credits").upsert(payload, on_conflict="user_id,month").execute()
        return {"ok": True, "credits_total": total, "credits_used": used, "credits_available": avail, "month": anchor_s}
    except Exception:
        pass

    try:
        _db().table("ai_credits").insert(payload).execute()
        return {"ok": True, "credits_total": total, "credits_used": used, "credits_available": avail, "month": anchor_s}
    except Exception as e:
        logging.exception("ai_credits create failed: %s", e)
        return {"ok": False, "credits_total": 0, "credits_used": 0, "credits_available": 0, "month": None}


def _consume_paid_credit(user_id: str, plan: str) -> None:
    uid = (user_id or "").strip()
    if not uid:
        return

    p = _normalize_plan(plan)
    if p == PLAN_FREE:
        return

    anchor = _plan_period_start(p, today_utc())
    anchor_s = str(anchor)

    row = _get_or_create_credit_row(uid, p)
    if not row.get("ok"):
        return

    total = int(row.get("credits_total") or 0)
    used = int(row.get("credits_used") or 0)
    new_used = used + 1
    new_avail = max(0, total - new_used)

    # Update (prefer update over upsert to avoid overwriting totals unexpectedly)
    try:
        _db().table("ai_credits").update(
            {
                "credits_used": new_used,
                "credits_available": new_avail,
                "plan": p,
            }
        ).eq("user_id", uid).eq("month", anchor_s).execute()
        return
    except Exception as e:
        logging.exception("ai_credits update failed (ignored): %s", e)

    # Fallback upsert
    try:
        _db().table("ai_credits").upsert(
            {
                "user_id": uid,
                "plan": p,
                "month": anchor_s,
                "credits_total": total,
                "credits_used": new_used,
                "credits_available": new_avail,
            },
            on_conflict="user_id,month",
        ).execute()
    except Exception as e2:
        logging.exception("ai_credits upsert fallback failed (ignored): %s", e2)


# -----------------------------
# Public API for engine.py
# -----------------------------
def can_use_ai(wa_phone: str) -> Dict[str, Any]:
    """
    Returns a decision dict consumed by engine.py.

    Allowed:
      { ok: True, plan, mode: "free_daily|credits", plan_expiry, user_id }

    Blocked:
      { ok: False, action: "upgrade|topup", reason, plan_expiry }
    """
    sub = _get_active_subscription(wa_phone)

    # Paid
    if sub.get("active"):
        plan = sub.get("plan")
        plan_expiry = sub.get("plan_expiry")
        user_id = sub.get("user_id")

        if not user_id:
            # Paid subscription exists but cannot locate user_id for credits table
            return {
                "ok": False,
                "action": "topup",
                "reason": "paid_user_id_missing",
                "plan_expiry": plan_expiry,
            }

        credit_row = _get_or_create_credit_row(user_id, plan)
        if not credit_row.get("ok"):
            return {
                "ok": False,
                "action": "topup",
                "reason": "credits_unavailable",
                "plan_expiry": plan_expiry,
            }

        avail = int(credit_row.get("credits_available") or 0)
        if avail <= 0:
            return {
                "ok": False,
                "action": "topup",
                "reason": "paid_credits_exhausted",
                "plan_expiry": plan_expiry,
            }

        return {
            "ok": True,
            "plan": plan,
            "mode": "credits",
            "plan_expiry": plan_expiry,
            "user_id": user_id,
        }

    # Free
    used_today = _get_free_daily_count(wa_phone)
    if used_today >= FREE_DAILY_LIMIT:
        return {"ok": False, "action": "upgrade", "reason": "free_daily_exhausted", "plan_expiry": None}

    return {"ok": True, "plan": PLAN_FREE, "mode": "free_daily", "plan_expiry": None, "user_id": None}


def consume_ai(wa_phone: str, plan: str, mode: str, user_id: Optional[str] = None) -> None:
    """
    Consumes one unit:
      - free_daily -> increments ai_daily_usage.count
      - credits -> increments ai_credits.credits_used and updates credits_available
    """
    m = (mode or "").lower().strip()

    if m == "free_daily":
        _inc_free_daily_count(wa_phone)
        return

    if m == "credits":
        uid = (user_id or "").strip()
        if not uid:
            # best-effort: try fetch from subscription
            sub = _get_active_subscription(wa_phone)
            uid = (sub.get("user_id") or "").strip()

        if uid:
            _consume_paid_credit(uid, plan)
        else:
            logging.error("consume_ai credits: missing user_id for wa_phone=%s", wa_phone)
        return


def log_ai_cost(wa_phone: str, question: str, answer: str, source: str = "ai") -> None:
    """
    Best-effort: your project previously logged to ai_cache or similar.
    We'll try ai_cache then ai_costs. If neither exists, ignore.
    """
    wa = (wa_phone or "").strip()
    if not wa:
        return

    payload = {
        "wa_phone": wa,
        "question": (question or "")[:1000],
        "answer": (answer or "")[:4000],
        "source": source,
        "created_at": iso(now_utc()),
    }

    try:
        _db().table("ai_cache").insert(payload).execute()
        return
    except Exception:
        pass

    try:
        _db().table("ai_costs").insert(payload).execute()
    except Exception as e:
        logging.exception("log_ai_cost failed (ignored): %s", e)
