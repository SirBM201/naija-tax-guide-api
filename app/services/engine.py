# app/services/engine.py
import logging
import os
from datetime import datetime, timezone, date
from typing import Dict, Any, Optional, Tuple

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question


# -----------------------------
# Config (safe defaults)
# -----------------------------
FREE_AI_PER_DAY = int(os.getenv("FREE_AI_PER_DAY", "2"))  # free plan: 2 AI/day
PAID_AI_PER_MONTH = int(os.getenv("PAID_AI_PER_MONTH", "300"))  # paid plans: 300 AI/month
AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() in ("1", "true", "yes")


# -----------------------------
# Supabase helper (lazy)
# -----------------------------
def _sb():
    """
    Lazy-load Supabase client so we don't crash on import if env isn't set.
    """
    try:
        from supabase import create_client  # type: ignore
    except Exception:
        return None

    url = (os.getenv("SUPABASE_URL") or "").strip()
    key = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
    if not url or not key:
        return None
    try:
        return create_client(url, key)
    except Exception:
        logging.exception("Supabase client init failed")
        return None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _today_utc() -> str:
    # store day as ISO date string e.g. 2026-01-24
    return date.today().isoformat()


def _get_active_subscription(sb, wa_phone: str) -> Optional[Dict[str, Any]]:
    """
    Reads from user_subscriptions:
      wa_phone, plan, status, expires_at
    """
    try:
        res = (
            sb.table("user_subscriptions")
            .select("wa_phone,plan,status,expires_at")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return None
        row = rows[0]
        if (row.get("status") or "").lower() != "active":
            return None
        exp = row.get("expires_at")
        if not exp:
            return None
        # expires_at may come as string
        exp_dt = None
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        except Exception:
            exp_dt = None
        if not exp_dt:
            return None
        if exp_dt <= _now_utc():
            return None
        row["_expires_dt"] = exp_dt
        return row
    except Exception:
        logging.exception("Failed reading user_subscriptions")
        return None


def _paid_quota_for_plan(plan: str) -> int:
    """
    300/month.
    quarterly = 900
    yearly = 3600
    """
    p = (plan or "").lower().strip()
    if p in ("monthly", "month"):
        return PAID_AI_PER_MONTH
    if p in ("quarterly", "quarter"):
        return PAID_AI_PER_MONTH * 3
    if p in ("yearly", "annual", "year"):
        return PAID_AI_PER_MONTH * 12
    # fallback if unknown plan name
    return PAID_AI_PER_MONTH


def _free_ai_allowed(sb, wa_phone: str) -> Tuple[bool, str]:
    """
    Enforce Free plan: 2 AI/day.
    Uses ai_daily_usage table best-effort:
      wa_phone (text), day (text or date), used (int)
    If table doesn't exist or query fails, we ALLOW (but log warning) to avoid breaking UX.
    """
    if not sb:
        return True, "no-db"

    day = _today_utc()
    try:
        res = (
            sb.table("ai_daily_usage")
            .select("wa_phone,day,used")
            .eq("wa_phone", wa_phone)
            .eq("day", day)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        used = int(rows[0].get("used") or 0) if rows else 0

        if used >= FREE_AI_PER_DAY:
            return False, f"free_limit_reached:{used}"

        # increment (upsert)
        new_used = used + 1
        sb.table("ai_daily_usage").upsert(
            {"wa_phone": wa_phone, "day": day, "used": new_used},
            on_conflict="wa_phone,day",
        ).execute()
        return True, f"free_ok:{new_used}"
    except Exception:
        logging.exception("ai_daily_usage check failed; allowing to avoid outage")
        return True, "free_check_failed_allowed"


def _paid_ai_allowed(sb, wa_phone: str, plan: str, expires_dt: datetime) -> Tuple[bool, str]:
    """
    Paid plans: quota is based on plan duration:
      monthly=300, quarterly=900, yearly=3600.
    We store remaining balance in ai_credits (best-effort):
      wa_phone, balance, expires_at, updated_at
    If table differs / missing, we ALLOW (but log) so app doesn't break.
    """
    if not sb:
        return True, "no-db"

    quota = _paid_quota_for_plan(plan)

    try:
        # read current balance
        res = (
            sb.table("ai_credits")
            .select("wa_phone,balance,expires_at")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            # initialize
            sb.table("ai_credits").upsert(
                {
                    "wa_phone": wa_phone,
                    "balance": quota - 1,
                    "expires_at": expires_dt.isoformat(),
                    "updated_at": _now_utc().isoformat(),
                },
                on_conflict="wa_phone",
            ).execute()
            return True, f"paid_init_used:1_remaining:{quota-1}"

        row = rows[0]
        bal = int(row.get("balance") or 0)

        # if stored expires_at is older than current subscription expiry, reset quota
        stored_exp = row.get("expires_at")
        reset = False
        if stored_exp:
            try:
                stored_exp_dt = datetime.fromisoformat(stored_exp.replace("Z", "+00:00"))
                if stored_exp_dt != expires_dt:
                    reset = True
            except Exception:
                reset = True
        else:
            reset = True

        if reset:
            bal = quota

        if bal <= 0:
            return False, "paid_quota_exhausted"

        bal2 = bal - 1
        sb.table("ai_credits").upsert(
            {
                "wa_phone": wa_phone,
                "balance": bal2,
                "expires_at": expires_dt.isoformat(),
                "updated_at": _now_utc().isoformat(),
            },
            on_conflict="wa_phone",
        ).execute()
        return True, f"paid_ok_remaining:{bal2}"
    except Exception:
        logging.exception("ai_credits check failed; allowing to avoid outage")
        return True, "paid_check_failed_allowed"


def _log_ai_suggestion(sb, q_norm: str, lang: str, answer: str, wa_phone: str, source: str) -> None:
    """
    Best-effort admin review queue:
    qa_suggestions table (you already have it).
    We try common columns; if your schema differs, it will just fail silently.
    """
    if not sb:
        return
    try:
        sb.table("qa_suggestions").insert(
            {
                "normalized_question": q_norm,
                "lang": lang,
                "answer": answer,
                "source": source,
                "status": "pending",
                "created_at": _now_utc().isoformat(),
                "wa_phone": wa_phone,
            }
        ).execute()
    except Exception:
        # don't crash the app due to admin-queue schema mismatch
        logging.info("qa_suggestions insert skipped (schema may differ)")


def _ai_generate_answer(question: str, lang: str = "en") -> str:
    """
    AI call is imported lazily to avoid boot-time crashes.
    You can implement app/services/ai.py with generate_answer().
    """
    if not AI_ENABLED:
        raise RuntimeError("AI disabled")

    try:
        from app.services.ai import generate_answer  # lazy import
    except Exception as e:
        raise RuntimeError(f"AI module import failed: {e}") from e

    return generate_answer(question=question, lang=lang)


def resolve_answer(
    wa_phone: str,
    question: str,
    mode: str = "text",
    lang: str = "en",
    source: str = "web",
) -> Dict[str, Any]:
    """
    Resolution order:
    1) qa_cache (by normalized_question)
    2) qa_library (by normalized_question + lang)
    3) AI fallback (with plan limits) + autosave (cache + admin suggestion)
    4) fallback message (if AI unavailable)
    """
    q_raw = (question or "").strip()
    q_norm = normalize_question(q_raw)

    logging.info(
        "ENGINE source=%s wa_phone=%s lang=%s mode=%s raw=%s norm=%s",
        source, wa_phone, lang, mode, q_raw[:120], q_norm[:120]
    )

    # 1) Cache
    try:
        cached = cache_get(q_norm)
    except Exception as e:
        logging.exception("cache_get failed (continuing without cache): %s", e)
        cached = None

    if cached and cached.get("answer"):
        return {"ok": True, "answer_text": cached["answer"], "source": "cache"}

    # 2) Library
    try:
        lib = library_get(q_norm, lang=lang)
    except Exception as e:
        logging.exception("library_get failed: %s", e)
        lib = None

    if lib and lib.get("answer"):
        ans = lib["answer"]

        # write-through cache
        try:
            cache_put(q_norm, ans, tags=["library"], source=source)
        except Exception as e:
            logging.exception("cache_put failed (ignored): %s", e)

        return {"ok": True, "answer_text": ans, "source": "library"}

    # 3) AI fallback (with plan usage limits)
    sb = _sb()

    # subscription check
    sub = _get_active_subscription(sb, wa_phone) if sb else None
    is_paid = bool(sub)
    expires_dt = sub.get("_expires_dt") if sub else None
    plan = sub.get("plan") if sub else "free"

    # enforce AI limits
    if is_paid and expires_dt:
        allowed, reason = _paid_ai_allowed(sb, wa_phone, plan=plan, expires_dt=expires_dt)
        if not allowed:
            return {
                "ok": False,
                "message": "Your AI quota for this plan is exhausted. Please top up AI credits or wait until your quota resets within your plan validity.",
                "reason": reason,
                "source": "ai_blocked",
            }
    else:
        allowed, reason = _free_ai_allowed(sb, wa_phone)
        if not allowed:
            return {
                "ok": False,
                "message": "Free plan AI limit reached for today (2/day). Please upgrade to continue.",
                "reason": reason,
                "source": "ai_blocked",
            }

    # generate AI answer
    try:
        ai_answer = _ai_generate_answer(question=q_raw, lang=lang)
    except Exception as e:
        logging.exception("AI fallback failed: %s", e)
        return {
            "ok": True,
            "answer_text": "I can help. Please ask your tax question (e.g., VAT, PAYE, TIN, filing, penalties).",
            "source": "fallback",
        }

    # autosave: cache + admin suggestion (best-effort)
    try:
        cache_put(q_norm, ai_answer, tags=["ai"], source=source)
    except Exception:
        logging.exception("cache_put(ai) failed (ignored)")

    try:
        _log_ai_suggestion(sb, q_norm=q_norm, lang=lang, answer=ai_answer, wa_phone=wa_phone, source=source)
    except Exception:
        pass

    return {"ok": True, "answer_text": ai_answer, "source": "ai"}
