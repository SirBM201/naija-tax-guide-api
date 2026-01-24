import logging
from datetime import datetime, timezone, date, timedelta
from typing import Any, Dict, Optional, Tuple

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def today_utc() -> date:
    return now_utc().date()

def _db():
    from app.db.supabase_client import supabase as get_supabase
    return get_supabase()

def _safe_get_first(res: Any) -> Optional[Dict[str, Any]]:
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None

def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        # Supabase returns ISO strings; Python can parse many ISO forms
        # If it lacks timezone, assume UTC.
        s = str(value)
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


# ------------------------------------------------------------
# Plan configuration (FINAL & AGREED)
# ------------------------------------------------------------

PLAN_FREE = "free"
PLAN_MONTHLY = "monthly"
PLAN_QUARTERLY = "quarterly"
PLAN_YEARLY = "yearly"

CREDITS_BY_PLAN = {
    PLAN_MONTHLY: 300,
    PLAN_QUARTERLY: 900,
    PLAN_YEARLY: 3600,
}

FREE_DAILY_LIMIT = 2


# ------------------------------------------------------------
# Subscription + Credits logic
# ------------------------------------------------------------

def _get_active_subscription(wa_phone: str) -> Dict[str, Any]:
    """
    Reads user_subscriptions for wa_phone.
    Expected columns (best effort):
      - wa_phone
      - plan (free/monthly/quarterly/yearly)
      - status (active)
      - expires_at (timestamptz)
    Returns:
      { "plan": str, "active": bool, "expires_at": datetime|None }
    """
    wa = (wa_phone or "").strip()
    if not wa:
        return {"plan": PLAN_FREE, "active": False, "expires_at": None}

    try:
        res = (
            _db()
            .table("user_subscriptions")
            .select("plan,status,expires_at")
            .eq("wa_phone", wa)
            .limit(1)
            .execute()
        )
        row = _safe_get_first(res)
        if not row:
            return {"plan": PLAN_FREE, "active": False, "expires_at": None}

        plan = (row.get("plan") or PLAN_FREE).lower().strip()
        status = (row.get("status") or "").lower().strip()
        exp = _parse_dt(row.get("expires_at"))

        # determine active
        active = False
        if status == "active" and exp and exp > now_utc():
            active = True

        if not active:
            return {"plan": PLAN_FREE, "active": False, "expires_at": exp}

        # normalize plan
        if plan not in (PLAN_MONTHLY, PLAN_QUARTERLY, PLAN_YEARLY):
            # Any unknown paid plan name falls back to monthly credits logic only if active
            # but safest is treat as monthly
            plan = PLAN_MONTHLY

        return {"plan": plan, "active": True, "expires_at": exp}

    except Exception as e:
        logging.exception("Failed to read user_subscriptions (fallback to free): %s", e)
        return {"plan": PLAN_FREE, "active": False, "expires_at": None}


def _ensure_credit_bucket(wa_phone: str, plan: str, plan_expires_at: datetime) -> Dict[str, Any]:
    """
    Ensures ai_credits has a row for this wa_phone for the current plan period.
    Best effort schema assumptions:
      ai_credits columns (typical):
        - wa_phone (unique)
        - plan
        - credits_remaining
        - expires_at
        - updated_at
        - created_at
    Returns:
      { "ok": True, "remaining": int, "expires_at": datetime }
    """
    wa = (wa_phone or "").strip()
    if not wa:
        return {"ok": False, "remaining": 0, "expires_at": None}

    default_credits = int(CREDITS_BY_PLAN.get(plan, 300))

    # 1) Read current credit record
    try:
        res = (
            _db()
            .table("ai_credits")
            .select("*")
            .eq("wa_phone", wa)
            .limit(1)
            .execute()
        )
        row = _safe_get_first(res)
    except Exception as e:
        logging.exception("ai_credits read failed: %s", e)
        row = None

    now = now_utc()

    if row:
        # Evaluate whether this bucket matches current plan period
        row_plan = (row.get("plan") or "").lower().strip()
        row_exp = _parse_dt(row.get("expires_at"))
        remaining = row.get("credits_remaining")

        try:
            remaining_int = int(remaining) if remaining is not None else 0
        except Exception:
            remaining_int = 0

        # If bucket is still valid for this plan period, return it
        if row_exp and row_exp > now and row_plan == plan:
            return {"ok": True, "remaining": max(0, remaining_int), "expires_at": row_exp}

        # Otherwise, reset bucket to match the active plan period
        try:
            _db().table("ai_credits").upsert(
                {
                    "wa_phone": wa,
                    "plan": plan,
                    "credits_remaining": default_credits,
                    "expires_at": iso(plan_expires_at),
                    "updated_at": iso(now),
                },
                on_conflict="wa_phone",
            ).execute()
            return {"ok": True, "remaining": default_credits, "expires_at": plan_expires_at}
        except Exception as e:
            logging.exception("ai_credits reset failed: %s", e)
            return {"ok": False, "remaining": 0, "expires_at": None}

    # No row exists: create it
    try:
        _db().table("ai_credits").upsert(
            {
                "wa_phone": wa,
                "plan": plan,
                "credits_remaining": default_credits,
                "expires_at": iso(plan_expires_at),
                "created_at": iso(now),
                "updated_at": iso(now),
            },
            on_conflict="wa_phone",
        ).execute()
        return {"ok": True, "remaining": default_credits, "expires_at": plan_expires_at}
    except Exception as e:
        logging.exception("ai_credits create failed: %s", e)
        return {"ok": False, "remaining": 0, "expires_at": None}


def _get_free_daily_usage(wa_phone: str) -> int:
    """
    Reads ai_daily_usage for today's usage for this wa_phone.
    Assumed columns:
      - wa_phone
      - day (date) OR used_on (date) OR created_at (timestamp)
      - used_count (int) or count (int)
    We'll implement a best-effort pattern:
      - prefer columns: wa_phone + day
      - used_count
    """
    wa = (wa_phone or "").strip()
    if not wa:
        return 0

    d = str(today_utc())
    try:
        res = (
            _db()
            .table("ai_daily_usage")
            .select("*")
            .eq("wa_phone", wa)
            .eq("day", d)
            .limit(1)
            .execute()
        )
        row = _safe_get_first(res)
        if row:
            v = row.get("used_count")
            try:
                return int(v) if v is not None else 0
            except Exception:
                return 0
    except Exception:
        # fallback below
        pass

    # Fallback: try used_on
    try:
        res = (
            _db()
            .table("ai_daily_usage")
            .select("*")
            .eq("wa_phone", wa)
            .eq("used_on", d)
            .limit(1)
            .execute()
        )
        row = _safe_get_first(res)
        if row:
            v = row.get("used_count") or row.get("count")
            try:
                return int(v) if v is not None else 0
            except Exception:
                return 0
    except Exception as e:
        logging.exception("ai_daily_usage read failed: %s", e)

    return 0


def _inc_free_daily_usage(wa_phone: str) -> None:
    """
    Increments today's free usage count (best effort).
    """
    wa = (wa_phone or "").strip()
    if not wa:
        return

    d = str(today_utc())
    current = _get_free_daily_usage(wa)

    # try update via upsert on (wa_phone,day)
    payload = {
        "wa_phone": wa,
        "day": d,
        "used_count": current + 1,
        "updated_at": iso(now_utc()),
    }

    try:
        _db().table("ai_daily_usage").upsert(payload, on_conflict="wa_phone,day").execute()
        return
    except Exception:
        pass

    # try upsert on (wa_phone,used_on)
    payload2 = {
        "wa_phone": wa,
        "used_on": d,
        "used_count": current + 1,
        "updated_at": iso(now_utc()),
    }
    try:
        _db().table("ai_daily_usage").upsert(payload2, on_conflict="wa_phone,used_on").execute()
        return
    except Exception:
        pass

    # fallback insert
    try:
        _db().table("ai_daily_usage").insert(payload).execute()
    except Exception as e:
        logging.exception("ai_daily_usage increment failed (ignored): %s", e)


# ------------------------------------------------------------
# Public API used by engine.py
# ------------------------------------------------------------

def can_use_ai(wa_phone: str) -> Dict[str, Any]:
    """
    Returns a decision dict consumed by engine.py.

    If allowed:
      { ok: True, plan: "free|monthly|quarterly|yearly", mode: "free_daily|credits", plan_expiry: str|None }

    If blocked:
      { ok: False, action: "upgrade|topup", reason: "...", plan_expiry: str|None }
    """
    sub = _get_active_subscription(wa_phone)

    # Paid plan
    if sub.get("active"):
        plan = sub.get("plan", PLAN_MONTHLY)
        exp_dt = sub.get("expires_at")
        plan_expiry = iso(exp_dt) if exp_dt else None

        bucket = _ensure_credit_bucket(wa_phone, plan, exp_dt) if exp_dt else {"ok": False, "remaining": 0}
        if not bucket.get("ok"):
            return {
                "ok": False,
                "action": "topup",
                "reason": "Unable to verify your AI credit balance. Please try again.",
                "plan_expiry": plan_expiry,
            }

        remaining = int(bucket.get("remaining") or 0)
        if remaining <= 0:
            return {
                "ok": False,
                "action": "topup",
                "reason": "paid_credits_exhausted",
                "plan_expiry": plan_expiry,
            }

        return {"ok": True, "plan": plan, "mode": "credits", "plan_expiry": plan_expiry}

    # Free plan
    used = _get_free_daily_usage(wa_phone)
    if used >= FREE_DAILY_LIMIT:
        return {"ok": False, "action": "upgrade", "reason": "free_daily_exhausted", "plan_expiry": None}

    return {"ok": True, "plan": PLAN_FREE, "mode": "free_daily", "plan_expiry": None}


def consume_ai(wa_phone: str, plan: str, mode: str) -> None:
    """
    Consumes one unit:
      - free_daily -> increments ai_daily_usage for today
      - credits -> decrements ai_credits.credits_remaining
    Best-effort: failures are logged but shouldn't crash app.
    """
    wa = (wa_phone or "").strip()
    if not wa:
        return

    mode = (mode or "").lower().strip()

    if mode == "free_daily":
        _inc_free_daily_usage(wa)
        return

    if mode == "credits":
        # decrement credits_remaining
        try:
            res = (
                _db()
                .table("ai_credits")
                .select("credits_remaining")
                .eq("wa_phone", wa)
                .limit(1)
                .execute()
            )
            row = _safe_get_first(res)
            remaining = 0
            if row and row.get("credits_remaining") is not None:
                try:
                    remaining = int(row.get("credits_remaining"))
                except Exception:
                    remaining = 0

            new_val = max(0, remaining - 1)

            _db().table("ai_credits").upsert(
                {
                    "wa_phone": wa,
                    "credits_remaining": new_val,
                    "updated_at": iso(now_utc()),
                },
                on_conflict="wa_phone",
            ).execute()
            return

        except Exception as e:
            logging.exception("consume_ai credits decrement failed (ignored): %s", e)
            return


def log_ai_cost(wa_phone: str, question: str, answer: str, source: str = "ai") -> None:
    """
    Best-effort logging to your cost table.

    You previously referenced 'ai_cache' for cost tracking, so we attempt:
      - ai_cache insert
    If schema mismatch, it is ignored.
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

    # try ai_cache
    try:
        _db().table("ai_cache").insert(payload).execute()
        return
    except Exception:
        pass

    # fallback: try ai_costs (if you use another table name)
    try:
        _db().table("ai_costs").insert(payload).execute()
    except Exception as e:
        logging.exception("log_ai_cost failed (ignored): %s", e)
