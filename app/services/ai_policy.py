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
    ai_credits has a 'month' (date) column. We store the plan period anchor there:
      - monthly    -> first day of month
      - quarterly  -> first day of quarter
      - yearly     -> Jan 1
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
# Identity resolution (KEY PART)
# -----------------------------
def _get_subscription_by_any_phone(user_phone: str) -> Dict[str, Any]:
    """
    IMPORTANT:
    - user_phone can be WhatsApp OR Telegram OR Web phone value
    - We resolve it to ONE subscription row
    - We require user_subscriptions.user_id (uuid) so ai_credits can work.

    Your table (from screenshot) includes:
      wa_phone, plan, status, expires_at, ... etc

    We are adding/using:
      tg_phone, user_id, primary_phone
    """
    p = (user_phone or "").strip()
    if not p:
        return {
            "found": False,
            "active": False,
            "plan": PLAN_FREE,
            "expires_at": None,
            "plan_expiry": None,
            "user_id": None,
            "primary_phone": None,
        }

    # Try extended columns first, fallback if DB not updated yet.
    try:
        res = (
            _db()
            .table("user_subscriptions")
            .select("wa_phone,tg_phone,primary_phone,user_id,plan,status,expires_at")
            .or_(f"wa_phone.eq.{p},tg_phone.eq.{p},primary_phone.eq.{p}")
            .limit(1)
            .execute()
        )
        row = _safe_first(res)
    except Exception as e:
        logging.warning("extended subscription select failed, fallback minimal: %s", e)
        try:
            res = (
                _db()
                .table("user_subscriptions")
                .select("wa_phone,plan,status,expires_at")
                .eq("wa_phone", p)
                .limit(1)
                .execute()
            )
            row = _safe_first(res)
        except Exception as e2:
            logging.exception("subscription read failed: %s", e2)
            row = None

    if not row:
        return {
            "found": False,
            "active": False,
            "plan": PLAN_FREE,
            "expires_at": None,
            "plan_expiry": None,
            "user_id": None,
            "primary_phone": None,
        }

    plan = _normalize_plan(row.get("plan") or PLAN_FREE)
    status = (row.get("status") or "").lower().strip()
    exp_dt = _parse_dt(row.get("expires_at"))
    uid = row.get("user_id")
    primary_phone = row.get("primary_phone") or row.get("wa_phone") or row.get("tg_phone")

    active = bool(status == "active" and exp_dt and exp_dt > now_utc() and plan != PLAN_FREE)
    plan_expiry = iso(exp_dt) if exp_dt else None

    return {
        "found": True,
        "active": active,
        "plan": plan if active else PLAN_FREE,
        "expires_at": exp_dt,
        "plan_expiry": plan_expiry,
        "user_id": str(uid) if uid else None,
        "primary_phone": str(primary_phone) if primary_phone else None,
        "wa_phone": row.get("wa_phone"),
        "tg_phone": row.get("tg_phone"),
    }


def _resolve_user_key(user_phone: str) -> Dict[str, Any]:
    """
    Returns:
      {
        ok: bool,
        user_key: str,   # used for free-daily usage table
        user_id: str|None,  # required for paid credits (ai_credits)
        plan: str,
        plan_expiry: str|None
      }

    Rule:
    - If subscription row exists and has primary_phone -> use it as user_key
    - Otherwise use provided phone as user_key (Telegram-only free users OK)
    """
    sub = _get_subscription_by_any_phone(user_phone)

    # canonical key for daily usage (must be SAME across channels)
    user_key = sub.get("primary_phone") or (user_phone or "").strip()

    return {
        "ok": True if user_key else False,
        "user_key": user_key,
        "user_id": sub.get("user_id"),
        "plan": sub.get("plan", PLAN_FREE),
        "active": sub.get("active", False),
        "plan_expiry": sub.get("plan_expiry"),
    }


# -----------------------------
# Free daily usage (ai_daily_usage)
# (we store user_key inside column wa_phone)
# -----------------------------
def _get_free_daily_count(user_key: str) -> int:
    k = (user_key or "").strip()
    if not k:
        return 0
    d = str(today_utc())

    try:
        res = (
            _db()
            .table("ai_daily_usage")
            .select("count")
            .eq("wa_phone", k)
            .eq("day", d)
            .limit(1)
            .execute()
        )
        row = _safe_first(res)
        if not row:
            return 0
        return int(row.get("count") or 0)
    except Exception as e:
        logging.exception("ai_daily_usage read failed: %s", e)
        return 0


def _inc_free_daily_count(user_key: str) -> None:
    k = (user_key or "").strip()
    if not k:
        return

    d = str(today_utc())
    current = _get_free_daily_count(k)
    new_val = current + 1

    # prefer upsert on (wa_phone, day) if unique constraint exists
    try:
        _db().table("ai_daily_usage").upsert(
            {"wa_phone": k, "day": d, "count": new_val, "last_used_at": iso(now_utc())},
            on_conflict="wa_phone,day",
        ).execute()
        return
    except Exception:
        pass

    # fallback update then insert
    try:
        _db().table("ai_daily_usage").update(
            {"count": new_val, "last_used_at": iso(now_utc())}
        ).eq("wa_phone", k).eq("day", d).execute()
        return
    except Exception:
        pass

    try:
        _db().table("ai_daily_usage").insert(
            {"wa_phone": k, "day": d, "count": new_val, "last_used_at": iso(now_utc())}
        ).execute()
    except Exception as e:
        logging.exception("ai_daily_usage increment failed (ignored): %s", e)


# -----------------------------
# Paid credits (ai_credits)
# -----------------------------
def _get_or_create_credit_row(user_id: str, plan: str) -> Dict[str, Any]:
    uid = (user_id or "").strip()
    if not uid:
        return {"ok": False, "credits_available": 0, "credits_used": 0, "credits_total": 0, "month": None}

    p = _normalize_plan(plan)
    if p == PLAN_FREE:
        return {"ok": False, "credits_available": 0, "credits_used": 0, "credits_total": 0, "month": None}

    anchor = _plan_period_start(p, today_utc())
    anchor_s = str(anchor)

    # read
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

    # create
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

    try:
        _db().table("ai_credits").update(
            {"credits_used": new_used, "credits_available": new_avail, "plan": p}
        ).eq("user_id", uid).eq("month", anchor_s).execute()
        return
    except Exception as e:
        logging.exception("ai_credits update failed (ignored): %s", e)

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
# Public API used by engine.py
# -----------------------------
def can_use_ai(user_phone: str) -> Dict[str, Any]:
    """
    user_phone may be WA phone or TG phone or Web phone.

    Returns:
      Allowed:
        { ok: True, plan, mode: "free_daily|credits", plan_expiry, user_key, user_id }
      Blocked:
        { ok: False, action: "upgrade|topup", reason, plan_expiry, user_key }
    """
    ident = _resolve_user_key(user_phone)
    if not ident.get("ok"):
        return {"ok": False, "action": "upgrade", "reason": "missing_user_phone", "plan_expiry": None, "user_key": None}

    user_key = ident["user_key"]

    # Paid
    if ident.get("active"):
        plan = ident.get("plan", PLAN_FREE)
        plan_expiry = ident.get("plan_expiry")
        user_id = ident.get("user_id")

        if not user_id:
            return {"ok": False, "action": "topup", "reason": "paid_user_id_missing", "plan_expiry": plan_expiry, "user_key": user_key}

        credit_row = _get_or_create_credit_row(user_id, plan)
        if not credit_row.get("ok"):
            return {"ok": False, "action": "topup", "reason": "credits_unavailable", "plan_expiry": plan_expiry, "user_key": user_key}

        avail = int(credit_row.get("credits_available") or 0)
        if avail <= 0:
            return {"ok": False, "action": "topup", "reason": "paid_credits_exhausted", "plan_expiry": plan_expiry, "user_key": user_key}

        return {"ok": True, "plan": plan, "mode": "credits", "plan_expiry": plan_expiry, "user_key": user_key, "user_id": user_id}

    # Free daily
    used_today = _get_free_daily_count(user_key)
    if used_today >= FREE_DAILY_LIMIT:
        return {"ok": False, "action": "upgrade", "reason": "free_daily_exhausted", "plan_expiry": None, "user_key": user_key}

    return {"ok": True, "plan": PLAN_FREE, "mode": "free_daily", "plan_expiry": None, "user_key": user_key, "user_id": None}


def consume_ai(user_phone: str, plan: str, mode: str, user_key: Optional[str] = None, user_id: Optional[str] = None) -> None:
    """
    Consumes one unit:
      - free_daily -> increments ai_daily_usage.count using user_key
      - credits    -> consumes ai_credits using user_id
    """
    m = (mode or "").lower().strip()

    # Resolve if missing
    if not user_key or (m == "credits" and not user_id):
        ident = _resolve_user_key(user_phone)
        user_key = user_key or ident.get("user_key")
        user_id = user_id or ident.get("user_id")

    if m == "free_daily":
        if user_key:
            _inc_free_daily_count(user_key)
        return

    if m == "credits":
        if user_id:
            _consume_paid_credit(user_id, plan)
        else:
            logging.error("consume_ai credits: missing user_id for phone=%s", user_phone)


def log_ai_cost(user_phone: str, question: str, answer: str, source: str = "ai") -> None:
    """
    Best-effort logging.
    """
    phone = (user_phone or "").strip()
    if not phone:
        return

    payload = {
        "wa_phone": phone,
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
