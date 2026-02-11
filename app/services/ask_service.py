# app/services/ask_service.py

from __future__ import annotations

import os
import re
from datetime import datetime, timezone, date
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase
from ..services.ai_service import ask_ai
from ..services.subscriptions_service import get_subscription_status

# ------------------------------------------------------------
# ENV / Config
# ------------------------------------------------------------
# Paid users:
# - Cache answers: soft limit (high) per day
# - AI answers: controlled ONLY by credit balance (no daily AI limit)
PAID_CACHE_DAILY_LIMIT = int((os.getenv("PAID_CACHE_DAILY_LIMIT", "1000") or "1000").strip())

# Hidden safety ceiling (applies to all paid questions: cache + AI)
# This is an anti-abuse / bot scraping guardrail.
HARD_DAILY_MAX = int((os.getenv("HARD_DAILY_MAX", "1500") or "1500").strip())

CACHE_MAX_RESULTS = int((os.getenv("CACHE_MAX_RESULTS", "1") or "1").strip())


# ------------------------------------------------------------
# Normalizers
# ------------------------------------------------------------
def _normalize_provider(provider: Optional[str]) -> Optional[str]:
    if not provider:
        return None
    p = provider.strip().lower()
    if p in ("whatsapp", "wa"):
        return "wa"
    if p in ("telegram", "tg"):
        return "tg"
    if p in ("web", "site", "website"):
        return "web"
    return p


def _normalize_mode(mode: Optional[str]) -> str:
    m = (mode or "text").strip().lower()
    return m if m in ("text", "voice") else "text"


def _normalize_lang(lang: Optional[str]) -> str:
    l = (lang or "en").strip().lower()
    return l or "en"


def _normalize_question_for_cache(question: str) -> str:
    q = (question or "").strip().lower()
    q = re.sub(r"[^\w\s]", " ", q)      # remove punctuation
    q = re.sub(r"\s+", " ", q).strip()  # collapse spaces
    return q


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _today_utc_date_str() -> str:
    return _now_utc().date().isoformat()


# ------------------------------------------------------------
# Costs (AI-only)
# ------------------------------------------------------------
def _cost_for_mode(mode: str) -> int:
    # Charged ONLY when AI is used (cache hits are always free)
    return 3 if mode == "voice" else 1


# ------------------------------------------------------------
# Logging (matches your current ai_usage_logs columns)
#   id, account_id (NOT NULL), question (nullable), answer (nullable), created_at
# ------------------------------------------------------------
def _log_usage_best_effort(account_id: str, question: str, answer: str) -> None:
    try:
        supabase().table("ai_usage_logs").insert(
            {
                "account_id": account_id,
                "question": question,
                "answer": answer,
                "created_at": _now_utc().isoformat(),
            }
        ).execute()
    except Exception:
        pass


# ------------------------------------------------------------
# QA Cache helpers
# ------------------------------------------------------------
def _find_cached_answer(normalized_question: str, lang: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id,answer,source,priority,lang,enabled")
            .eq("normalized_question", normalized_question)
            .eq("lang", lang)
            .eq("enabled", True)
            .order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(CACHE_MAX_RESULTS)
            .execute()
        )
        if res.data:
            return res.data[0]
    except Exception:
        pass
    return None


def _touch_cache_best_effort(row_id: str) -> None:
    if not row_id:
        return

    # Prefer atomic RPC if present
    try:
        supabase().rpc("touch_qa_cache", {"p_id": row_id}).execute()
        return
    except Exception:
        pass

    # fallback (best effort)
    try:
        got = supabase().table("qa_cache").select("use_count").eq("id", row_id).limit(1).execute()
        cur = 0
        if got.data:
            cur = int(got.data[0].get("use_count") or 0)
        supabase().table("qa_cache").update(
            {"use_count": cur + 1, "last_used_at": _now_utc().isoformat()}
        ).eq("id", row_id).execute()
    except Exception:
        pass


def _upsert_ai_answer_to_cache_best_effort(normalized_question: str, answer: str, lang: str) -> None:
    """
    Best effort cache fill so future repeats are free/fast.
    """
    if not normalized_question or not answer:
        return
    now_iso = _now_utc().isoformat()

    try:
        existing = (
            supabase()
            .table("qa_cache")
            .select("id")
            .eq("normalized_question", normalized_question)
            .eq("lang", lang)
            .limit(1)
            .execute()
        )

        if existing.data:
            row_id = existing.data[0]["id"]
            supabase().table("qa_cache").update(
                {
                    "answer": answer,
                    "source": "ai",
                    "enabled": True,
                    "last_used_at": now_iso,
                }
            ).eq("id", row_id).execute()
            return

        supabase().table("qa_cache").insert(
            {
                "normalized_question": normalized_question,
                "answer": answer,
                "tags": [],
                "use_count": 0,
                "last_used_at": now_iso,
                "created_at": now_iso,
                "source": "ai",
                "enabled": True,
                "priority": 0,
                "lang": lang,
            }
        ).execute()
    except Exception:
        pass


# ------------------------------------------------------------
# Daily usage counters (PAID USERS)
# We use your existing daily_question_usage + RPC bump_daily_question_usage if available.
#
# We will track two counters per day:
# 1) cache_usage_today (soft limit = PAID_CACHE_DAILY_LIMIT)
# 2) total_usage_today (hard limit = HARD_DAILY_MAX)  [cache + AI]
#
# Implementation:
# - We keep using daily_question_usage as TOTAL counter (hard max).
# - We store cache counter in daily_question_counters(cache_used) if available.
#   If daily_question_counters doesn't exist or fails, we fail open for cache soft-limit
#   but still enforce HARD_DAILY_MAX via daily_question_usage.
# ------------------------------------------------------------
def _bump_total_daily_usage(account_id: str, limit_per_day: int) -> Tuple[bool, int]:
    """
    Increments TOTAL daily usage (cache + AI).
    Returns (allowed, used_today_after_increment_or_current).
    Enforces HARD_DAILY_MAX.
    """
    day_str = _today_utc_date_str()
    day = date.fromisoformat(day_str)

    # Prefer atomic RPC
    try:
        res = supabase().rpc(
            "bump_daily_question_usage",
            {"p_account_id": account_id, "p_day": day.isoformat(), "p_limit": int(limit_per_day)},
        ).execute()
        data = res.data or {}
        if isinstance(data, list):
            data = data[0] if data else {}
        if data.get("ok"):
            return True, int(data.get("daily_used") or 0)
        return False, int(data.get("daily_used") or 0)
    except Exception:
        pass

    # Fallback: best-effort total counter
    try:
        got = (
            supabase()
            .table("daily_question_usage")
            .select("count")
            .eq("account_id", account_id)
            .eq("day", day_str)
            .limit(1)
            .execute()
        )
        cur = 0
        if got.data:
            cur = int(got.data[0].get("count") or 0)

        if cur >= int(limit_per_day):
            return False, cur

        if got.data:
            supabase().table("daily_question_usage").update(
                {"count": cur + 1}
            ).eq("account_id", account_id).eq("day", day_str).execute()
            return True, cur + 1

        supabase().table("daily_question_usage").insert(
            {"account_id": account_id, "day": day_str, "count": 1}
        ).execute()
        return True, 1
    except Exception:
        # fail open (do not block) if table misbehaves
        return True, 0


def _get_paid_cache_used(account_id: str) -> int:
    """
    Reads cache_used for today from daily_question_counters.
    If table doesn't exist / errors -> return 0 (fail open on soft cache limit).
    """
    day_str = _today_utc_date_str()
    try:
        got = (
            supabase()
            .table("daily_question_counters")
            .select("cache_used")
            .eq("account_id", account_id)
            .eq("day", day_str)
            .limit(1)
            .execute()
        )
        if got.data:
            return int(got.data[0].get("cache_used") or 0)
    except Exception:
        pass
    return 0


def _bump_paid_cache_used(account_id: str) -> int:
    """
    Increments cache_used for today in daily_question_counters.
    Returns cache_used after increment.
    If table doesn't exist / errors -> returns current/0 (fail open on soft cache limit).
    """
    day_str = _today_utc_date_str()

    # Prefer atomic RPC if present (optional)
    # bump_daily_question_counters(p_account_id, p_day, p_kind) -> {cache_used, ai_used}
    try:
        res = supabase().rpc(
            "bump_daily_question_counters",
            {"p_account_id": account_id, "p_day": day_str, "p_kind": "cache"},
        ).execute()
        data = res.data or {}
        if isinstance(data, list):
            data = data[0] if data else {}
        if "cache_used" in data:
            return int(data["cache_used"] or 0)
    except Exception:
        pass

    # Fallback: upsert row then increment
    try:
        got = (
            supabase()
            .table("daily_question_counters")
            .select("cache_used,ai_used")
            .eq("account_id", account_id)
            .eq("day", day_str)
            .limit(1)
            .execute()
        )

        if got.data:
            row = got.data[0]
            cache_used = int(row.get("cache_used") or 0) + 1
            ai_used = int(row.get("ai_used") or 0)
            supabase().table("daily_question_counters").update(
                {"cache_used": cache_used, "ai_used": ai_used}
            ).eq("account_id", account_id).eq("day", day_str).execute()
            return cache_used

        # create new row
        supabase().table("daily_question_counters").insert(
            {"account_id": account_id, "day": day_str, "cache_used": 1, "ai_used": 0}
        ).execute()
        return 1
    except Exception:
        return 0


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def ask_guarded(body: Dict[str, Any]) -> Dict[str, Any]:
    account_id = (body.get("account_id") or "").strip() or None
    provider = _normalize_provider((body.get("provider") or "").strip() or None)
    provider_user_id = (body.get("provider_user_id") or "").strip() or None

    question = (body.get("question") or "").strip()
    lang = _normalize_lang(body.get("lang"))
    mode = _normalize_mode(body.get("mode"))

    if not question:
        return {"ok": False, "reason": "missing_question", "message": "Question is required.", "plan_expiry": None}

    # Subscription guard (paid-only system)
    status = get_subscription_status(
        account_id=account_id,
        provider=provider,
        provider_user_id=provider_user_id,
    )

    if not status.get("active"):
        return {
            "ok": False,
            "reason": status.get("reason", "not_subscribed"),
            "message": "Subscription required to ask questions.",
            "plan_expiry": status.get("expires_at"),
        }

    aid = (status.get("account_id") or account_id or "").strip() or None
    if not aid:
        return {
            "ok": False,
            "reason": "account_not_found",
            "message": "Account not found.",
            "plan_expiry": status.get("expires_at"),
        }

    normalized_q = _normalize_question_for_cache(question)

    # 0) HARD anti-abuse ceiling: bump TOTAL counter first (cache + AI)
    hard_allowed, hard_used_today = _bump_total_daily_usage(aid, HARD_DAILY_MAX)
    if not hard_allowed:
        return {
            "ok": False,
            "reason": "hard_daily_max_reached",
            "message": "Daily maximum usage reached. Please try again tomorrow or contact support if you need higher limits.",
            "plan_expiry": status.get("expires_at"),
            "daily_used": hard_used_today,
            "daily_limit": HARD_DAILY_MAX,
        }

    # 1) Cache first (free, but soft-limited)
    cached = _find_cached_answer(normalized_q, lang)
    if cached and cached.get("answer"):
        # Enforce soft cache limit (1000/day) — but do NOT block AI credits here,
        # because this path is cache-hit only.
        cache_used = _get_paid_cache_used(aid)
        if cache_used >= PAID_CACHE_DAILY_LIMIT:
            return {
                "ok": False,
                "reason": "cache_limit_reached",
                "message": f"Daily cache limit reached ({PAID_CACHE_DAILY_LIMIT}/day). Try asking a different question (may use AI credits) or try again tomorrow.",
                "plan_expiry": status.get("expires_at"),
                "cache_used": cache_used,
                "cache_limit": PAID_CACHE_DAILY_LIMIT,
                "daily_used": hard_used_today,
                "daily_limit": HARD_DAILY_MAX,
            }

        ans = cached["answer"]
        _touch_cache_best_effort(cached.get("id") or "")
        cache_used2 = _bump_paid_cache_used(aid)
        _log_usage_best_effort(aid, question, ans)

        return {
            "ok": True,
            "answer": ans,
            "audio_url": None,
            "mode": mode,
            "used_cache": True,
            "ai_hit": False,
            "cost": 0,
            "credits_remaining": None,
            "plan_expiry": status.get("expires_at"),
            "cache_used": cache_used2,
            "cache_limit": PAID_CACHE_DAILY_LIMIT,
            "daily_used": hard_used_today,
            "daily_limit": HARD_DAILY_MAX,
        }

    # 2) Cache miss => AI credits ONLY (no daily AI throttle)
    cost = _cost_for_mode(mode)

    # IMPORTANT: function args must match: (p_account_id uuid, p_cost integer)
    try:
        spend = supabase().rpc("consume_ai_credits", {"p_account_id": aid, "p_cost": int(cost)}).execute()
        spend_data: Any = spend.data or {}
        if isinstance(spend_data, list):
            spend_data = spend_data[0] if spend_data else {}
    except Exception:
        spend_data = {"ok": False, "reason": "ledger_error"}

    if not spend_data.get("ok"):
        reason = spend_data.get("reason") or "out_of_credits"

        if reason in ("expired", "not_subscribed"):
            return {
                "ok": False,
                "reason": reason,
                "message": "Subscription is not active. Please subscribe.",
                "plan_expiry": status.get("expires_at"),
                "daily_used": hard_used_today,
                "daily_limit": HARD_DAILY_MAX,
            }

        if reason == "insufficient_credits":
            return {
                "ok": False,
                "reason": "out_of_credits",
                "message": "You have used up your AI credits. Please renew your subscription.",
                "plan_expiry": status.get("expires_at"),
                "credits_remaining": spend_data.get("credits_remaining"),
                "daily_used": hard_used_today,
                "daily_limit": HARD_DAILY_MAX,
            }

        return {
            "ok": False,
            "reason": reason,
            "message": "Request blocked. Please try again or contact support.",
            "plan_expiry": status.get("expires_at"),
            "daily_used": hard_used_today,
            "daily_limit": HARD_DAILY_MAX,
        }

    answer = ask_ai(question, lang=lang)

    # If AI failed, refund credit (best effort)
    if not answer or "AI service not configured" in (answer or ""):
        try:
            supabase().rpc("refund_ai_credits", {"p_account_id": aid, "p_cost": int(cost)}).execute()
        except Exception:
            pass
        return {
            "ok": False,
            "reason": "ai_not_configured",
            "message": "AI service not configured yet. Please try again later.",
            "plan_expiry": status.get("expires_at"),
            "daily_used": hard_used_today,
            "daily_limit": HARD_DAILY_MAX,
        }

    _upsert_ai_answer_to_cache_best_effort(normalized_q, answer, lang)
    _log_usage_best_effort(aid, question, answer)

    return {
        "ok": True,
        "answer": answer,
        "audio_url": None,
        "mode": mode,
        "used_cache": False,
        "ai_hit": True,
        "cost": cost,
        "credits_remaining": spend_data.get("credits_remaining"),
        "plan_expiry": status.get("expires_at"),
        "daily_used": hard_used_today,
        "daily_limit": HARD_DAILY_MAX,
        "cache_limit": PAID_CACHE_DAILY_LIMIT,
    }
