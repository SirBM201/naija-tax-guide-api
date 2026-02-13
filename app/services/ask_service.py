# app/services/ask_service.py
from __future__ import annotations

from typing import Dict, Any, Optional, Tuple
from datetime import date
import time

from ..core.supabase_client import supabase
from .qa_cache_service import find_cached_answer, touch_cache_best_effort, upsert_ai_answer_to_cache_best_effort
from .qa_library_service import find_library_answer
from .qa_logging_service import log_qa_event_best_effort


PAID_CACHE_DAILY_LIMIT = 1000  # ✅ paid users cache/day
# ✅ No paid AI daily limit. AI usage is controlled ONLY by AI credits.


def _today_utc() -> str:
    return date.today().isoformat()


def _normalize_question(q: str) -> str:
    return " ".join((q or "").strip().lower().split())


def _get_or_create_daily_counter(account_id: str, day: str) -> Dict[str, Any]:
    res = (
        supabase().table("daily_question_counters")
        .select("*")
        .eq("account_id", account_id)
        .eq("day", day)
        .limit(1)
        .execute()
    )
    if getattr(res, "data", None):
        return res.data[0]

    payload = {
        "account_id": account_id,
        "day": day,
        "total_count": 0,
        "text_count": 0,
        "voice_count": 0,
        "cache_count": 0,
        "ai_count": 0,
    }
    ins = supabase().table("daily_question_counters").insert(payload).execute()
    if getattr(ins, "data", None):
        return ins.data[0]
    return payload


def _update_daily_counter_best_effort(
    account_id: str,
    day: str,
    *,
    mode: str,
    used_cache: bool,
    used_ai: bool,
) -> None:
    try:
        row = _get_or_create_daily_counter(account_id, day)
        supabase().table("daily_question_counters").update({
            "total_count": int(row.get("total_count") or 0) + 1,
            "text_count": int(row.get("text_count") or 0) + (1 if mode == "text" else 0),
            "voice_count": int(row.get("voice_count") or 0) + (1 if mode == "voice" else 0),
            "cache_count": int(row.get("cache_count") or 0) + (1 if used_cache else 0),
            "ai_count": int(row.get("ai_count") or 0) + (1 if used_ai else 0),
        }).eq("account_id", account_id).eq("day", day).execute()
    except Exception:
        return


def _paid_cache_used_today(account_id: str, day: str) -> int:
    try:
        row = _get_or_create_daily_counter(account_id, day)
        return int(row.get("cache_count") or 0)
    except Exception:
        return 0


def _consume_ai_credits(account_id: str, cost: int) -> Tuple[bool, str]:
    """
    Uses your confirmed signature:
      consume_ai_credits(p_account_id, p_cost)
    Must return ok/reason pattern or boolean.
    """
    cost = int(cost or 0)
    if cost <= 0:
        return True, "ok"

    try:
        spend = supabase().rpc("consume_ai_credits", {"p_account_id": account_id, "p_cost": cost}).execute()
        data = getattr(spend, "data", None) or {}

        if isinstance(data, list):
            data = data[0] if data else {}

        # handle dict style: {"ok": true/false, "reason": "..."}
        if isinstance(data, dict):
            if data.get("ok") is True:
                return True, "ok"
            return False, (data.get("reason") or "out_of_credits")

        # handle boolean style
        if data is True:
            return True, "ok"

        return False, "out_of_credits"
    except Exception:
        return False, "ledger_error"


def _cost_for_mode(mode: str) -> int:
    # you can tune later
    return 1 if mode == "text" else 2


def _call_ai_model(question: str, lang: str = "en") -> str:
    """
    Replace with your real AI provider call.
    Keep as stub so boot is always safe.
    """
    return f"(AI) I received your question: {question}"


def answer_question(
    *,
    account_id: str,
    question: str,
    lang: str = "en",
    canonical_key: Optional[str] = None,
    mode: str = "text",            # text|voice
    is_paid_user: bool = True,     # your subscription layer sets this
    plan_active: bool = True,      # pass your computed plan status here
    cache_tags: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Returns ONLY answer or a clean topup-required error.
    Does not expose cache/ai sources to users.
    """
    t0 = time.time()

    account_id = (account_id or "").strip()
    q_raw = (question or "").strip()
    lang = (lang or "en").strip() or "en"
    mode = (mode or "text").strip().lower()
    if mode not in ("text", "voice"):
        mode = "text"

    if not account_id or not q_raw:
        latency = int((time.time() - t0) * 1000)
        log_qa_event_best_effort(
            account_id=account_id or "unknown",
            mode=mode,
            lang=lang,
            question_raw=q_raw,
            normalized_question="",
            canonical_key=canonical_key,
            outcome="blocked",
            reason="validation_error",
            source=None,
            cache_hit=False,
            library_hit=False,
            ai_used=False,
            ai_credit_cost=0,
            latency_ms=latency,
        )
        return {"ok": False, "error": "INVALID_REQUEST", "message": "account_id and question are required."}

    day = _today_utc()
    nq = _normalize_question(q_raw)

    # 1) Library first
    lib = find_library_answer(nq, lang=lang, canonical_key=canonical_key)
    if lib and lib.get("answer"):
        latency = int((time.time() - t0) * 1000)
        _update_daily_counter_best_effort(account_id, day, mode=mode, used_cache=True, used_ai=False)
        log_qa_event_best_effort(
            account_id=account_id,
            mode=mode,
            lang=lang,
            question_raw=q_raw,
            normalized_question=nq,
            canonical_key=canonical_key,
            outcome="ok",
            reason=None,
            source="library",
            cache_hit=False,
            library_hit=True,
            ai_used=False,
            ai_credit_cost=0,
            latency_ms=latency,
        )
        return {"ok": True, "answer": lib.get("answer")}

    # 2) Cache next (paid limit applies)
    cache_allowed = True
    if is_paid_user:
        if _paid_cache_used_today(account_id, day) >= PAID_CACHE_DAILY_LIMIT:
            cache_allowed = False

    if cache_allowed:
        cached = find_cached_answer(nq, lang=lang, canonical_key=canonical_key)
        if cached and cached.get("answer"):
            touch_cache_best_effort(str(cached.get("id")))
            latency = int((time.time() - t0) * 1000)
            _update_daily_counter_best_effort(account_id, day, mode=mode, used_cache=True, used_ai=False)
            log_qa_event_best_effort(
                account_id=account_id,
                mode=mode,
                lang=lang,
                question_raw=q_raw,
                normalized_question=nq,
                canonical_key=canonical_key,
                outcome="ok",
                reason=None,
                source="cache",
                cache_hit=True,
                library_hit=False,
                ai_used=False,
                ai_credit_cost=0,
                latency_ms=latency,
            )
            return {"ok": True, "answer": cached.get("answer")}

    # 3) AI fallback (credits only)
    cost = _cost_for_mode(mode)
    ok, reason = _consume_ai_credits(account_id, cost)

    if not ok:
        latency = int((time.time() - t0) * 1000)

        # Log internal block
        log_qa_event_best_effort(
            account_id=account_id,
            mode=mode,
            lang=lang,
            question_raw=q_raw,
            normalized_question=nq,
            canonical_key=canonical_key,
            outcome="blocked",
            reason="ai_credits_exhausted" if reason in ("out_of_credits", "insufficient_credits") else reason,
            source=None,
            cache_hit=False,
            library_hit=False,
            ai_used=False,
            ai_credit_cost=0,
            latency_ms=latency,
        )

        # User-facing: no credit numbers, no source
        if plan_active:
            return {
                "ok": False,
                "error": "AI_TOPUP_REQUIRED",
                "message": "You’ve reached your AI usage limit for your current plan. Please top up AI credits to continue receiving AI answers.",
            }
        return {
            "ok": False,
            "error": "SUBSCRIPTION_REQUIRED",
            "message": "Your subscription is not active. Please renew to continue.",
        }

    # AI success
    ai_answer = _call_ai_model(q_raw, lang=lang)

    upsert_ai_answer_to_cache_best_effort(
        normalized_question=nq,
        answer=ai_answer,
        tags=cache_tags,
        source="ai",
        lang=lang,
        canonical_key=canonical_key,
        enabled=True,
        priority=0,
    )

    latency = int((time.time() - t0) * 1000)
    _update_daily_counter_best_effort(account_id, day, mode=mode, used_cache=False, used_ai=True)

    # Internal log includes cost, but user never sees it
    log_qa_event_best_effort(
        account_id=account_id,
        mode=mode,
        lang=lang,
        question_raw=q_raw,
        normalized_question=nq,
        canonical_key=canonical_key,
        outcome="ok",
        reason=None,
        source="ai",
        cache_hit=False,
        library_hit=False,
        ai_used=True,
        ai_credit_cost=cost,
        latency_ms=latency,
    )

    return {"ok": True, "answer": ai_answer}
