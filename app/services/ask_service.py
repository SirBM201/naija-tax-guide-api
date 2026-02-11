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
# PAID USERS
PAID_CACHE_DAILY_LIMIT = int((os.getenv("PAID_CACHE_DAILY_LIMIT", "1000") or "1000").strip())
HARD_DAILY_MAX = int((os.getenv("HARD_DAILY_MAX", "1500") or "1500").strip())

# FREE USERS (no active plan)
FREE_CACHE_DAILY_LIMIT = int((os.getenv("FREE_CACHE_DAILY_LIMIT", "20") or "20").strip())
FREE_AI_DAILY_LIMIT = int((os.getenv("FREE_AI_DAILY_LIMIT", "1") or "1").strip())

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
    """
    Must match how you populate qa_cache.normalized_question.
    """
    q = (question or "").strip().lower()
    q = re.sub(r"[^\w\s]", " ", q)      # remove punctuation
    q = re.sub(r"\s+", " ", q).strip()  # collapse spaces
    return q


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _today_utc_date_str() -> str:
    return _now_utc().date().isoformat()


# ------------------------------------------------------------
# Costs (AI credits only; cache is free)
# ------------------------------------------------------------
def _cost_for_mode(mode: str) -> int:
    # Only charged when AI credits are used
    return 3 if mode == "voice" else 1


# ------------------------------------------------------------
# Logging (matches your ai_usage_logs columns)
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
# HARD DAILY MAX (total questions/day) for PAID + FREE
# Uses your existing daily_question_usage table + bump_daily_question_usage RPC (if available)
# IMPORTANT: We "check first" then "bump after success" to avoid counting failed requests.
# ------------------------------------------------------------
def _get_total_used_today(account_id: str) -> int:
    day_str = _today_utc_date_str()
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
        if got.data:
            return int(got.data[0].get("count") or 0)
    except Exception:
        pass
    return 0


def _bump_total_used_today_best_effort(account_id: str, hard_limit: int) -> int:
    """
    Returns the new total used today after bump (best effort).
    """
    day_str = _today_utc_date_str()
    day = date.fromisoformat(day_str)

    # Prefer atomic RPC if present
    try:
        res = supabase().rpc(
            "bump_daily_question_usage",
            {"p_account_id": account_id, "p_day": day.isoformat(), "p_limit": int(hard_limit)},
        ).execute()
        data = res.data or {}
        if isinstance(data, list):
            data = data[0] if data else {}
        # If ok, daily_used is already the bumped value
        if "daily_used" in data:
            return int(data.get("daily_used") or 0)
    except Exception:
        pass

    # Fallback upsert/increment
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
            supabase().table("daily_question_usage").update(
                {"count": cur + 1}
            ).eq("account_id", account_id).eq("day", day_str).execute()
            return cur + 1

        supabase().table("daily_question_usage").insert(
            {"account_id": account_id, "day": day_str, "count": 1}
        ).execute()
        return 1
    except Exception:
        # fail open
        return _get_total_used_today(account_id)


# ------------------------------------------------------------
# Free daily counters (separate cache_used and ai_used)
# Table: daily_question_counters(account_id, day, cache_used, ai_used)
# ------------------------------------------------------------
def _get_free_counters(account_id: str) -> Tuple[int, int]:
    day_str = _today_utc_date_str()
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
            return int(row.get("cache_used") or 0), int(row.get("ai_used") or 0)
    except Exception:
        pass
    return 0, 0


def _bump_free_counter(account_id: str, which: str) -> Tuple[int, int]:
    """
    which: "cache" or "ai"
    returns: (cache_used, ai_used) after bump
    """
    day_str = _today_utc_date_str()

    # Prefer atomic RPC if you add it
    try:
        res = supabase().rpc(
            "bump_daily_question_counters",
            {"p_account_id": account_id, "p_day": day_str, "p_kind": which},
        ).execute()
        data = res.data or {}
        if isinstance(data, list):
            data = data[0] if data else {}
        if "cache_used" in data and "ai_used" in data:
            return int(data["cache_used"] or 0), int(data["ai_used"] or 0)
    except Exception:
        pass

    # Fallback: upsert row then increment (best effort)
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

        cache_used = 0
        ai_used = 0
        if got.data:
            row = got.data[0]
            cache_used = int(row.get("cache_used") or 0)
            ai_used = int(row.get("ai_used") or 0)

            if which == "cache":
                cache_used += 1
            else:
                ai_used += 1

            supabase().table("daily_question_counters").update(
                {"cache_used": cache_used, "ai_used": ai_used}
            ).eq("account_id", account_id).eq("day", day_str).execute()
            return cache_used, ai_used

        # create new row
        cache_used = 1 if which == "cache" else 0
        ai_used = 1 if which == "ai" else 0
        supabase().table("daily_question_counters").insert(
            {"account_id": account_id, "day": day_str, "cache_used": cache_used, "ai_used": ai_used}
        ).execute()
        return cache_used, ai_used
    except Exception:
        # fail open
        return 0, 0


# ------------------------------------------------------------
# Paid cache counter (reuses same daily_question_counters table)
# Table: daily_question_counters(account_id, day, cache_used, ai_used)
# For PAID: we only care about cache_used limit (1000). ai_used optional.
# ------------------------------------------------------------
def _get_paid_cache_used(account_id: str) -> int:
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
    cache_used, _ai_used = _bump_free_counter(account_id, "cache")
    return int(cache_used or 0)


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

    # Resolve subscription/account info
    status = get_subscription_status(
        account_id=account_id,
        provider=provider,
        provider_user_id=provider_user_id,
    )

    aid = (status.get("account_id") or account_id or "").strip() or None
    if not aid:
        return {"ok": False, "reason": "account_not_found", "message": "Account not found.", "plan_expiry": status.get("expires_at")}

    normalized_q = _normalize_question_for_cache(question)

    # HARD cap check (total questions/day) for everyone
    total_used = _get_total_used_today(aid)
    if total_used >= HARD_DAILY_MAX:
        return {
            "ok": False,
            "reason": "hard_daily_max_reached",
            "message": f"Daily usage cap reached ({HARD_DAILY_MAX}/day). Please try again tomorrow.",
            "plan_expiry": status.get("expires_at"),
            "daily_used": total_used,
            "daily_limit": HARD_DAILY_MAX,
        }

    # ============================================================
    # 1) CACHE FIRST (ALWAYS) — this is what prevents AI spending
    # ============================================================
    cached = _find_cached_answer(normalized_q, lang)

    # ----------------------------
    # FREE USERS (no active plan)
    # ----------------------------
    if not status.get("active"):
        # Cache hit for free
        if cached and cached.get("answer"):
            cache_used, ai_used = _get_free_counters(aid)
            if cache_used >= FREE_CACHE_DAILY_LIMIT:
                return {
                    "ok": False,
                    "reason": "free_cache_limit_reached",
                    "message": f"Free daily cache limit reached ({FREE_CACHE_DAILY_LIMIT}/day). Please subscribe for more access.",
                    "plan_expiry": None,
                    "daily_used": cache_used + ai_used,
                    "daily_limit": FREE_CACHE_DAILY_LIMIT + FREE_AI_DAILY_LIMIT,
                }

            ans = cached["answer"]
            _touch_cache_best_effort(cached.get("id") or "")
            cache_used2, ai_used2 = _bump_free_counter(aid, "cache")
            new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)
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
                "plan_expiry": None,
                "daily_used": new_total,
                "daily_limit": HARD_DAILY_MAX,
                "free_cache_used": cache_used2,
                "free_ai_used": ai_used2,
            }

        # Cache miss => allow 1 AI/day for free (no ledger)
        cache_used, ai_used = _get_free_counters(aid)
        if ai_used >= FREE_AI_DAILY_LIMIT:
            return {
                "ok": False,
                "reason": "free_ai_limit_reached",
                "message": f"Free daily AI limit reached ({FREE_AI_DAILY_LIMIT}/day). Please subscribe to continue.",
                "plan_expiry": None,
                "daily_used": cache_used + ai_used,
                "daily_limit": FREE_CACHE_DAILY_LIMIT + FREE_AI_DAILY_LIMIT,
            }

        answer = ask_ai(question, lang=lang)
        if not answer:
            return {
                "ok": False,
                "reason": "ask_failed",
                "message": "AI temporarily unavailable. Please try again later.",
                "plan_expiry": None,
                "daily_used": total_used,
                "daily_limit": HARD_DAILY_MAX,
            }

        cache_used2, ai_used2 = _bump_free_counter(aid, "ai")
        new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)

        _upsert_ai_answer_to_cache_best_effort(normalized_q, answer, lang)
        _log_usage_best_effort(aid, question, answer)

        return {
            "ok": True,
            "answer": answer,
            "audio_url": None,
            "mode": mode,
            "used_cache": False,
            "ai_hit": True,
            "cost": 0,
            "credits_remaining": None,
            "plan_expiry": None,
            "daily_used": new_total,
            "daily_limit": HARD_DAILY_MAX,
            "free_cache_used": cache_used2,
            "free_ai_used": ai_used2,
        }

    # ----------------------------
    # PAID USERS (active plan)
    # ----------------------------
    # If cache hit => enforce PAID cache limit (1000/day) ONLY on cache hits
    if cached and cached.get("answer"):
        cache_used = _get_paid_cache_used(aid)
        if cache_used >= PAID_CACHE_DAILY_LIMIT:
            return {
                "ok": False,
                "reason": "paid_cache_limit_reached",
                "message": f"Daily cache limit reached ({PAID_CACHE_DAILY_LIMIT}/day). Please try again tomorrow.",
                "plan_expiry": status.get("expires_at"),
                "daily_used": total_used,
                "daily_limit": HARD_DAILY_MAX,
                "cache_used": cache_used,
                "cache_limit": PAID_CACHE_DAILY_LIMIT,
            }

        ans = cached["answer"]
        _touch_cache_best_effort(cached.get("id") or "")
        cache_used2 = _bump_paid_cache_used(aid)
        new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)
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
            "daily_used": new_total,
            "daily_limit": HARD_DAILY_MAX,
            "cache_used": cache_used2,
            "cache_limit": PAID_CACHE_DAILY_LIMIT,
        }

    # Cache miss => AI path (AI controlled by credit balance ONLY)
    cost = _cost_for_mode(mode)

    try:
        spend = supabase().rpc("consume_ai_credits", {"p_account_id": aid, "p_cost": cost}).execute()
        spend_data: Any = spend.data or {}
        if isinstance(spend_data, list):
            spend_data = spend_data[0] if spend_data else {}
    except Exception:
        spend_data = {"ok": False, "reason": "ledger_error"}

    if not spend_data.get("ok"):
        reason = spend_data.get("reason") or "out_of_credits"

        if reason == "insufficient_credits":
            return {
                "ok": False,
                "reason": "out_of_credits",
                "message": "You have used up your AI credits. Please renew your subscription.",
                "plan_expiry": status.get("expires_at"),
                "credits_remaining": spend_data.get("credits_remaining"),
                "daily_used": total_used,
                "daily_limit": HARD_DAILY_MAX,
                "cache_limit": PAID_CACHE_DAILY_LIMIT,
            }

        return {
            "ok": False,
            "reason": reason,
            "message": "Request blocked. Please try again or contact support.",
            "plan_expiry": status.get("expires_at"),
            "daily_used": total_used,
            "daily_limit": HARD_DAILY_MAX,
            "cache_limit": PAID_CACHE_DAILY_LIMIT,
        }

    answer = ask_ai(question, lang=lang)

    # If AI failed, refund credit (best effort)
    if not answer:
        try:
            supabase().rpc("refund_ai_credits", {"p_account_id": aid, "p_cost": cost}).execute()
        except Exception:
            pass
        return {
            "ok": False,
            "reason": "ask_failed",
            "message": "AI temporarily unavailable. Please try again later.",
            "plan_expiry": status.get("expires_at"),
            "daily_used": total_used,
            "daily_limit": HARD_DAILY_MAX,
            "cache_limit": PAID_CACHE_DAILY_LIMIT,
        }

    new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)

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
        "daily_used": new_total,
        "daily_limit": HARD_DAILY_MAX,
        "cache_limit": PAID_CACHE_DAILY_LIMIT,
    }
