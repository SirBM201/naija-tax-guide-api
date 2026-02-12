# app/services/ask_service.py
from __future__ import annotations

import os
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
from ..services.qa_library_service import find_library_answer
from ..services.response_refiner import refine_answer
from ..services.question_canonicalizer import basic_normalize, canonical_key


# ------------------------------------------------------------
# Supabase wrapper (supports both supabase() and supabase styles)
# ------------------------------------------------------------
def _sb():
    try:
        return supabase()  # type: ignore
    except TypeError:
        return supabase


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
        _sb().table("ai_usage_logs").insert(
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
# HARD DAILY MAX (daily_question_usage.count)
# ------------------------------------------------------------
def _get_total_used_today(account_id: str) -> int:
    day_str = _today_utc_date_str()
    try:
        got = (
            _sb()
            .table("daily_question_usage")
            .select("count")
            .eq("account_id", account_id)
            .eq("day", day_str)
            .limit(1)
            .execute()
        )
        rows = getattr(got, "data", None) or []
        if rows:
            return int(rows[0].get("count") or 0)
    except Exception:
        pass
    return 0


def _bump_total_used_today_best_effort(account_id: str, hard_limit: int) -> int:
    day_str = _today_utc_date_str()
    day = date.fromisoformat(day_str)

    # Prefer RPC (atomic)
    try:
        res = _sb().rpc(
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
            _sb()
            .table("daily_question_usage")
            .select("count")
            .eq("account_id", account_id)
            .eq("day", day_str)
            .limit(1)
            .execute()
        )
        rows = getattr(got, "data", None) or []
        if rows:
            cur = int(rows[0].get("count") or 0)
            _sb().table("daily_question_usage").update({"count": cur + 1}).eq("account_id", account_id).eq("day", day_str).execute()
            return cur + 1

        _sb().table("daily_question_usage").insert({"account_id": account_id, "day": day_str, "count": 1}).execute()
        return 1
    except Exception:
        return _get_total_used_today(account_id)


# ------------------------------------------------------------
# daily_question_counters (uses your real columns)
# Columns:
#   total_count, text_count, voice_count, cache_count, ai_count, updated_at
# ------------------------------------------------------------
def _get_counters(account_id: str) -> Tuple[int, int]:
    """
    Returns (cache_count, ai_count) for today.
    """
    day_str = _today_utc_date_str()
    try:
        got = (
            _sb()
            .table("daily_question_counters")
            .select("cache_count,ai_count")
            .eq("account_id", account_id)
            .eq("day", day_str)
            .limit(1)
            .execute()
        )
        rows = getattr(got, "data", None) or []
        if rows:
            row = rows[0]
            return int(row.get("cache_count") or 0), int(row.get("ai_count") or 0)
    except Exception:
        pass
    return 0, 0


def _bump_counters_best_effort(account_id: str, *, kind: str, mode: str) -> Tuple[int, int]:
    """
    Increments today's counters.
    kind: "cache" | "ai"
    mode: "text" | "voice"  (affects text_count/voice_count)
    Returns (cache_count, ai_count) after bump (best-effort).
    """
    day_str = _today_utc_date_str()
    now_iso = _now_utc().isoformat()

    kind = (kind or "").strip().lower()
    mode = (mode or "text").strip().lower()
    if kind not in ("cache", "ai"):
        kind = "cache"
    if mode not in ("text", "voice"):
        mode = "text"

    # Prefer RPC if you have it (optional)
    try:
        res = _sb().rpc(
            "bump_daily_question_counters",
            {"p_account_id": account_id, "p_day": day_str, "p_kind": kind, "p_mode": mode},
        ).execute()
        data = res.data or {}
        if isinstance(data, list):
            data = data[0] if data else {}
        # Accept either naming style from RPC implementations
        if "cache_count" in data and "ai_count" in data:
            return int(data.get("cache_count") or 0), int(data.get("ai_count") or 0)
        if "cache_used" in data and "ai_used" in data:
            return int(data.get("cache_used") or 0), int(data.get("ai_used") or 0)
    except Exception:
        pass

    # Fallback: read + write
    try:
        got = (
            _sb()
            .table("daily_question_counters")
            .select("total_count,text_count,voice_count,cache_count,ai_count")
            .eq("account_id", account_id)
            .eq("day", day_str)
            .limit(1)
            .execute()
        )
        rows = getattr(got, "data", None) or []

        if rows:
            row = rows[0]
            total_count = int(row.get("total_count") or 0)
            text_count = int(row.get("text_count") or 0)
            voice_count = int(row.get("voice_count") or 0)
            cache_count = int(row.get("cache_count") or 0)
            ai_count = int(row.get("ai_count") or 0)

            total_count += 1
            if mode == "voice":
                voice_count += 1
            else:
                text_count += 1

            if kind == "ai":
                ai_count += 1
            else:
                cache_count += 1

            _sb().table("daily_question_counters").update(
                {
                    "total_count": total_count,
                    "text_count": text_count,
                    "voice_count": voice_count,
                    "cache_count": cache_count,
                    "ai_count": ai_count,
                    "updated_at": now_iso,
                }
            ).eq("account_id", account_id).eq("day", day_str).execute()

            return cache_count, ai_count

        # Row does not exist yet -> insert with defaults (NOT NULL columns)
        total_count = 1
        text_count = 1 if mode == "text" else 0
        voice_count = 1 if mode == "voice" else 0
        cache_count = 1 if kind == "cache" else 0
        ai_count = 1 if kind == "ai" else 0

        _sb().table("daily_question_counters").insert(
            {
                "account_id": account_id,
                "day": day_str,
                "total_count": total_count,
                "text_count": text_count,
                "voice_count": voice_count,
                "cache_count": cache_count,
                "ai_count": ai_count,
                "updated_at": now_iso,
            }
        ).execute()
        return cache_count, ai_count

    except Exception:
        return _get_counters(account_id)


def _get_paid_cache_used(account_id: str) -> int:
    cache_count, _ = _get_counters(account_id)
    return int(cache_count or 0)


def _bump_paid_cache_used(account_id: str, mode: str) -> int:
    cache_count, _ = _bump_counters_best_effort(account_id, kind="cache", mode=mode)
    return int(cache_count or 0)


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

    normalized_q = basic_normalize(question)
    ckey = canonical_key(question)

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
    # 1) QA_LIBRARY FIRST (free + paid) — no credit cost
    # ============================================================
    lib = find_library_answer(canonical_key=ckey, normalized_question=normalized_q, lang=lang)
    if lib and (lib.get("answer") or "").strip():
        ans = (lib["answer"] or "").strip()
        ans2 = refine_answer(ans, lang=lang, source="library", provider=provider or "web") or ans

        new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)
        # (Optional) You can count library usage into total_count if you want:
        # _bump_counters_best_effort(aid, kind="cache", mode=mode)  # not recommended; leave it clean.

        _log_usage_best_effort(aid, question, ans2)

        return {
            "ok": True,
            "answer": ans2,
            "audio_url": None,
            "mode": mode,
            "used_cache": False,
            "used_library": True,
            "ai_hit": False,
            "cost": 0,
            "credits_remaining": None,
            "plan_expiry": status.get("expires_at") if status.get("active") else None,
            "daily_used": new_total,
            "daily_limit": HARD_DAILY_MAX,
            "canonical_key": ckey,
        }

    # ============================================================
    # 2) CACHE NEXT (free + paid)
    # ============================================================
    cached = find_cached_answer(
        canonical_key=ckey,
        normalized_question=normalized_q,
        lang=lang,
        max_results=CACHE_MAX_RESULTS,
    )

    # ----------------------------
    # FREE USERS
    # ----------------------------
    if not status.get("active"):
        cache_count, ai_count = _get_counters(aid)

        if cached and cached.get("answer"):
            if cache_count >= FREE_CACHE_DAILY_LIMIT:
                return {
                    "ok": False,
                    "reason": "free_cache_limit_reached",
                    "message": f"Free daily cache limit reached ({FREE_CACHE_DAILY_LIMIT}/day). Please subscribe for more access.",
                    "plan_expiry": None,
                    "daily_used": cache_count + ai_count,
                    "daily_limit": FREE_CACHE_DAILY_LIMIT + FREE_AI_DAILY_LIMIT,
                }

            ans = cached["answer"]
            touch_cache_best_effort(cached.get("id") or "")

            cache_count2, ai_count2 = _bump_counters_best_effort(aid, kind="cache", mode=mode)
            new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)

            ans2 = refine_answer(ans, lang=lang, source="cache", provider=provider or "web") or ans
            _log_usage_best_effort(aid, question, ans2)

            return {
                "ok": True,
                "answer": ans2,
                "audio_url": None,
                "mode": mode,
                "used_cache": True,
                "used_library": False,
                "ai_hit": False,
                "cost": 0,
                "credits_remaining": None,
                "plan_expiry": None,
                "daily_used": new_total,
                "daily_limit": HARD_DAILY_MAX,
                "free_cache_used": cache_count2,
                "free_ai_used": ai_count2,
                "canonical_key": ckey,
            }

        # Cache miss => free AI/day cap
        if ai_count >= FREE_AI_DAILY_LIMIT:
            return {
                "ok": False,
                "reason": "free_ai_limit_reached",
                "message": f"Free daily AI limit reached ({FREE_AI_DAILY_LIMIT}/day). Please subscribe to continue.",
                "plan_expiry": None,
                "daily_used": cache_count + ai_count,
                "daily_limit": FREE_CACHE_DAILY_LIMIT + FREE_AI_DAILY_LIMIT,
            }

        raw = ask_ai(question, lang=lang)
        refined = refine_answer(raw or "", lang=lang, source="ai", provider=provider or "web")

        if not refined:
            return {
                "ok": False,
                "reason": "ask_failed",
                "message": "AI temporarily unavailable. Please try again later.",
                "plan_expiry": None,
                "daily_used": total_used,
                "daily_limit": HARD_DAILY_MAX,
            }

        cache_count2, ai_count2 = _bump_counters_best_effort(aid, kind="ai", mode=mode)
        new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)

        # Cache ONLY AI refined success answers (NOT library)
        upsert_ai_answer_to_cache_best_effort(
            canonical_key=ckey,
            normalized_question=normalized_q,
            answer=refined,
            lang=lang,
        )

        _log_usage_best_effort(aid, question, refined)

        return {
            "ok": True,
            "answer": refined,
            "audio_url": None,
            "mode": mode,
            "used_cache": False,
            "used_library": False,
            "ai_hit": True,
            "cost": 0,
            "credits_remaining": None,
            "plan_expiry": None,
            "daily_used": new_total,
            "daily_limit": HARD_DAILY_MAX,
            "free_cache_used": cache_count2,
            "free_ai_used": ai_count2,
            "canonical_key": ckey,
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
        cache_used2 = _bump_paid_cache_used(aid, mode=mode)
        new_total = _bump_total_used_today_best_effort(aid, HARD_DAILY_MAX)

        ans2 = refine_answer(ans, lang=lang, source="cache", provider=provider or "web") or ans
        _log_usage_best_effort(aid, question, ans2)

        return {
            "ok": True,
            "answer": ans2,
            "audio_url": None,
            "mode": mode,
            "used_cache": True,
            "used_library": False,
            "ai_hit": False,
            "cost": 0,
            "credits_remaining": None,
            "plan_expiry": status.get("expires_at"),
            "daily_used": new_total,
            "daily_limit": HARD_DAILY_MAX,
            "cache_used": cache_used2,
            "cache_limit": PAID_CACHE_DAILY_LIMIT,
            "canonical_key": ckey,
        }

    # Cache miss => AI with credit ledger
    cost = _cost_for_mode(mode)

    try:
        spend = _sb().rpc("consume_ai_credits", {"p_account_id": aid, "p_cost": cost}).execute()
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
    refined = refine_answer(raw or "", lang=lang, source="ai", provider=provider or "web")

    # AI failed => refund credits, do NOT cache
    if not refined:
        try:
            _sb().rpc("refund_ai_credits", {"p_account_id": aid, "p_cost": cost}).execute()
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

    # Cache ONLY refined AI answers
    upsert_ai_answer_to_cache_best_effort(
        canonical_key=ckey,
        normalized_question=normalized_q,
        answer=refined,
        lang=lang,
    )
    _log_usage_best_effort(aid, question, refined)

    return {
        "ok": True,
        "answer": refined,
        "audio_url": None,
        "mode": mode,
        "used_cache": False,
        "used_library": False,
        "ai_hit": True,
        "cost": cost,
        "credits_remaining": spend_data.get("credits_remaining"),
        "plan_expiry": status.get("expires_at"),
        "daily_used": new_total,
        "daily_limit": HARD_DAILY_MAX,
        "cache_limit": PAID_CACHE_DAILY_LIMIT,
        "canonical_key": ckey,
    }
