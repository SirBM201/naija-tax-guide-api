# app/services/ask_service.py

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase
from ..services.ai_service import ask_ai
from ..services.subscriptions_service import get_subscription_status

# ------------------------------------------------------------
# ENV / Config
# ------------------------------------------------------------
# Paid plan: cache-only daily limit (AI is unlimited but credit-controlled)
PAID_CACHE_DAILY_LIMIT = int((os.getenv("PAID_CACHE_DAILY_LIMIT", "300") or "300").strip())

# Free (no active plan) limits
FREE_CACHE_DAILY_LIMIT = int((os.getenv("FREE_CACHE_DAILY_LIMIT", "20") or "20").strip())
FREE_AI_DAILY_LIMIT = int((os.getenv("FREE_AI_DAILY_LIMIT", "1") or "1").strip())

CACHE_MAX_RESULTS = int((os.getenv("CACHE_MAX_RESULTS", "1") or "1").strip())


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _today_utc_date_str() -> str:
    return _now_utc().date().isoformat()


def _is_uuid(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        uuid.UUID(value.strip())
        return True
    except Exception:
        return False


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
    q = re.sub(r"[^\w\s]", " ", q)       # remove punctuation
    q = re.sub(r"\s+", " ", q).strip()   # collapse spaces
    return q


# ------------------------------------------------------------
# Costs
# ------------------------------------------------------------
def _cost_for_mode(mode: str) -> int:
    # Only charged when PAID users consume AI credits
    return 3 if mode == "voice" else 1


# ------------------------------------------------------------
# Logging (matches ai_usage_logs columns)
#   id, account_id (NOT NULL), question, answer, created_at
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
# Daily counters (cache_used + ai_used)
# Table: daily_question_counters(account_id, day, cache_used, ai_used)
# We use this for BOTH free and paid:
# - Free: enforce cache_used + ai_used via separate limits
# - Paid: enforce ONLY cache_used limit; AI is credit-controlled, not daily-limited
# ------------------------------------------------------------
def _get_counters(account_id: str) -> Tuple[int, int]:
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
    """
    which: "cache" or "ai"
    returns: (cache_used, ai_used) after bump
    """
    day_str = _today_utc_date_str()

    # Prefer atomic RPC if you add it later:
    # bump_daily_question_counters(p_account_id, p_day, p_kind) -> {cache_used, ai_used}
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

    # Guard: account_id must be a full UUID if provided
    if account_id and not _is_uuid(account_id):
        return {
            "ok": False,
            "reason": "invalid_account_id",
            "message": "Invalid Account ID. Please paste the full account_id from Dashboard (must be a full UUID).",
            "plan_expiry": None,
        }

    status = get_subscription_status(
        account_id=account_id,
        provider=provider,
        provider_user_id=provider_user_id,
    )

    aid = (status.get("account_id") or account_id or "").strip() or None
    if not aid:
        return {"ok": False, "reason": "account_not_found", "message": "Account not found.", "plan_expiry": status.get("expires_at")}

    if not _is_uuid(aid):
        return {
            "ok": False,
            "reason": "invalid_account_id",
            "message": "Invalid Account ID. Please paste the full account_id from Dashboard (must be a full UUID).",
            "plan_expiry": status.get("expires_at"),
        }

    normalized_q = _normalize_question_for_cache(question)

    # Always try cache first
    cached = _find_cached_answer(normalized_q, lang)

    # ============================================================
    # FREE USERS (no active plan): 20 cache/day + 1 AI/day
    # ============================================================
    if not status.get("active"):
        # Cache hit path
        if cached and cached.get("answer"):
            cache_used, ai_used = _get_counters(aid)

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
            cache_used2, ai_used2 = _bump_counter(aid, "cache")
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
                "daily_used": cache_used2 + ai_used2,
                "daily_limit": FREE_CACHE_DAILY_LIMIT + FREE_AI_DAILY_LIMIT,
            }

        # Cache miss => allow max 1 AI/day (NO ledger for free)
        cache_used, ai_used = _get_counters(aid)
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
        if not answer or "AI service not configured" in (answer or ""):
            return {
                "ok": False,
                "reason": "ai_not_configured",
                "message": "AI service not configured yet. Please try again later.",
                "plan_expiry": None,
                "daily_used": cache_used + ai_used,
                "daily_limit": FREE_CACHE_DAILY_LIMIT + FREE_AI_DAILY_LIMIT,
            }

        cache_used2, ai_used2 = _bump_counter(aid, "ai")
        _upsert_ai_answer_to_cache_best_effort(normalized_q, answer, lang)
        _log_usage_best_effort(aid, question, answer)

        return {
            "ok": True,
            "answer": answer,
            "audio_url": None,
            "mode": mode,
            "used_cache": False,
            "ai_hit": True,
            "cost": 0,  # free AI doesn't spend credits
            "credits_remaining": None,
            "plan_expiry": None,
            "daily_used": cache_used2 + ai_used2,
            "daily_limit": FREE_CACHE_DAILY_LIMIT + FREE_AI_DAILY_LIMIT,
        }

    # ============================================================
    # PAID USERS (active plan):
    # - Cache answers/day limited to PAID_CACHE_DAILY_LIMIT
    # - AI is NOT daily limited; ONLY credit balance controls AI
    # ============================================================
    cache_used, ai_used = _get_counters(aid)

    # If cache exists, enforce paid cache daily limit before returning it
    if cached and cached.get("answer"):
        if cache_used >= PAID_CACHE_DAILY_LIMIT:
            # Cache limit reached -> do NOT return cache; user can still use AI via credits
            # We intentionally proceed to AI path below.
            cached = None
        else:
            ans = cached["answer"]
            _touch_cache_best_effort(cached.get("id") or "")
            cache_used2, ai_used2 = _bump_counter(aid, "cache")
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
            }

    # Cache miss OR cache limit reached -> PAID AI path (credit ledger controls)
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
                "cache_used": cache_used,
                "cache_limit": PAID_CACHE_DAILY_LIMIT,
            }

        if reason in ("expired", "not_subscribed"):
            return {
                "ok": False,
                "reason": reason,
                "message": "Subscription is not active. Please subscribe.",
                "plan_expiry": status.get("expires_at"),
                "cache_used": cache_used,
                "cache_limit": PAID_CACHE_DAILY_LIMIT,
            }

        return {
            "ok": False,
            "reason": reason,
            "message": "Request blocked. Please try again or contact support.",
            "plan_expiry": status.get("expires_at"),
            "cache_used": cache_used,
            "cache_limit": PAID_CACHE_DAILY_LIMIT,
        }

    answer = ask_ai(question, lang=lang)

    # If AI failed, refund credit (best effort)
    if not answer or "AI service not configured" in (answer or ""):
        try:
            supabase().rpc("refund_ai_credits", {"p_account_id": aid, "p_cost": cost}).execute()
        except Exception:
            pass
        return {
            "ok": False,
            "reason": "ai_not_configured",
            "message": "AI service not configured yet. Please try again later.",
            "plan_expiry": status.get("expires_at"),
            "cache_used": cache_used,
            "cache_limit": PAID_CACHE_DAILY_LIMIT,
        }

    # Optional: you can bump ai_used for paid users too (analytics only), but it is NOT a limit
    # Keeping it for reporting visibility:
    cache_used2, ai_used2 = _bump_counter(aid, "ai")

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
        "cache_used": cache_used2,
        "cache_limit": PAID_CACHE_DAILY_LIMIT,
        "ai_used_today": ai_used2,  # analytics only, NOT a limit
    }
