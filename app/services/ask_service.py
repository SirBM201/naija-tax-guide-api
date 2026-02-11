# app/services/ask_service.py
from __future__ import annotations

import os
import re
from datetime import datetime, timezone, date
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase
from ..services.ai_service import ask_ai
from ..services.subscriptions_service import get_subscription_status
from ..services.qa_cache_service import (
    find_cached_answer,
    touch_cache_best_effort,
    upsert_ai_answer_to_cache_best_effort,
)
from ..services.response_refiner import refine_answer

# ------------------------------------------------------------
# ENV / Config
# ------------------------------------------------------------
PAID_CACHE_DAILY_LIMIT = int((os.getenv("PAID_CACHE_DAILY_LIMIT", "1000") or "1000").strip())
HARD_DAILY_MAX = int((os.getenv("HARD_DAILY_MAX", "1500") or "1500").strip())

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
    q = (question or "").strip().lower()
    q = re.sub(r"[^\w\s]", " ", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _today_utc_date_str() -> str:
    return _now_utc().date().isoformat()


# ------------------------------------------------------------
# Costs (AI credits only)
# ------------------------------------------------------------
def _cost_for_mode(mode: str) -> int:
    return 3 if mode == "voice" else 1


# ------------------------------------------------------------
# Logging
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
# HARD DAILY MAX
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
    day_str = _today_utc_date_str()
    day = date.fromisoformat(day_str)

    # Prefer RPC (atomic)
    try:
        res = supabase().rpc(
            "bump_daily_question_usage",
            {"p_account_id": account_id, "p_day": day.isoformat(), "p_limit": int(hard_limit)},
        ).execute()
        data = res.data or {}
        if isinstance(data, list):
            data = data[0] if data else {}
        if "daily_used" in data:
            return int(data.get("daily_used") or 0)
    except Exception:
        pass

    # Fallback (best-effort)
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
            supabase().table("daily_question_usage").update({"count": cur + 1}).eq("account_id", account_id).eq("day", day_str).execute()
            return cur + 1

        supabase().table("daily_question_usage").insert({"account_id": account_id, "day": day_str, "count": 1}).execute()
        return 1
    except Exception:
        return _get_total_used_today(account_id)


# ------------------------------------------------------------
# daily_question_counters (free + paid cache tracking)
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


def _bump_counter(account_id: str, which: str) -> Tuple[int, int]:
    day_str = _today_utc_date_str()

    # Prefer RPC (atomic)
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

    # Fallback (best-effort)
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

            supabase().table("daily_question_counters").update({"cache_used": cache_used, "ai_used": ai_used}).eq("account_id", account_id).eq("day", day_str).execute()
            return cache_used, ai_used

        cache_used = 1 if which == "cache" else 0
        ai_used = 1 if which == "ai" else 0
        supabase().table("daily_question_counters").insert({"account_id": account_id, "day": day_str, "cache_used": cache_used, "ai_used": ai_used}).execute()
        return cache_used, ai_used
    except Exception:
        return 0, 0


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
    cache_used, _ = _bump_counter(account_id, "cache")
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

    status = get_subscription_status(account_id=account_id, provider=provider, provider_user_id=provider_user_id)

    aid = (status.get("account_id") or account_id or "").strip() or None
    if not aid:
        return {"ok": False, "reason": "account_not_found", "message": "Account not found.", "plan_expiry": status.get("expires_at")}

    normalized_q = _normalize_question_for_cache(question)

    # HARD cap check
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
    # CACHE FIRST (ALWAYS) — also ignores poisoned cache entries
    # ============================================================
    cached = find_cached_answer(normalized_q, lang, max_results=CACHE_MAX_RESULTS)

    # ----------------------------
    # FREE USERS
    # ----------------------------
    if not status.get("active"):
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
            touch_cache_best_effort(cached.get("id") or "")
            cache_used2, ai_used2 = _bump_counter(aid, "cache")
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

        # Cache miss => free AI/day cap
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

        raw = ask_ai(question, lang=lang)
        refined = refine_answer(raw or "", lang=lang, source="ai")

        if not refined:
            return {
                "ok": False,
                "reason": "ask_failed",
                "message": "AI temporarily unavailable. Please try again later.",
                "plan_expiry": None,
                "daily_used": total_used,
                "daily_limit": HARD_DAILY_MAX,
            }

        cache_used2, ai_used2 = _bump_counter(aid, "ai")
        new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)

        # Cache ONLY refined success answers
        upsert_ai_answer_to_cache_best_effort(normalized_q, refined, lang)
        _log_usage_best_effort(aid, question, refined)

        return {
            "ok": True,
            "answer": refined,
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
    # PAID USERS
    # ----------------------------
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
        touch_cache_best_effort(cached.get("id") or "")
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

    # Cache miss => AI with credit ledger
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
        if reason in ("insufficient_credits", "out_of_credits"):
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

    raw = ask_ai(question, lang=lang)
    refined = refine_answer(raw or "", lang=lang, source="ai")

    # AI failed => refund credits, do NOT cache
    if not refined:
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

    # Cache ONLY refined success answers
    upsert_ai_answer_to_cache_best_effort(normalized_q, refined, lang)
    _log_usage_best_effort(aid, question, refined)

    return {
        "ok": True,
        "answer": refined,
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
