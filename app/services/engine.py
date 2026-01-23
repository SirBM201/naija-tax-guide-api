# app/services/engine.py
from typing import Any, Dict
import logging

from app.core.config import (
    VOICE_AI_COST, TEXT_AI_COST, VOICE_CACHED_FIRST_GEN_COST,
)
from app.core.utils import normalize_phone, normalize_question
from app.services.answers import format_markdown_answer
from app.services.ai import ai_answer_text
from app.services.voice import ensure_voice_for_text
from app.services.enforcement import enforce_daily_total_limit_or_message, can_use_ai_for_cost
from app.db.qa import library_get, cache_get, cache_set
from app.db.usage import daily_total_usage_inc, ai_daily_usage_inc
from app.db.ledger import ledger_add

def resolve_answer(
    wa_phone: str,
    question: str,
    mode: str,
    voice_provider: str = "openai",
    voice_style: str = "default",
    lang: str = "en",
    source: str = "web",
    **_ignored: Any,
) -> Dict[str, Any]:
    wa_phone = normalize_phone(wa_phone)
    question = (question or "").strip()
    nq = normalize_question(question)

    msg = enforce_daily_total_limit_or_message(wa_phone)
    if msg:
        formatted = format_markdown_answer(question, msg)
        return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "limit"}}

    # 1) Library
    lib_ans = library_get(question, lang)
    if lib_ans:
        formatted = format_markdown_answer(question, lib_ans)
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)

        if mode == "voice":
            audio_url, generated_now = ensure_voice_for_text(nq, formatted, voice_provider, voice_style)
            credits_used = 0
            if generated_now:
                allowed, _reason = can_use_ai_for_cost(wa_phone, VOICE_CACHED_FIRST_GEN_COST)
                if not allowed:
                    return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "library", "voice": "blocked"}}
                credits_used = VOICE_CACHED_FIRST_GEN_COST
                ledger_add(wa_phone, -credits_used, "tts_cached_gen")
            return {"ok": True, "answer_text": formatted, "audio_url": audio_url, "credits_used": credits_used, "meta": {"source": "library"}}

        return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "library"}}

    # 2) Cache
    cached = cache_get(question)
    if cached:
        formatted = format_markdown_answer(question, cached)
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)

        if mode == "voice":
            audio_url, generated_now = ensure_voice_for_text(nq, formatted, voice_provider, voice_style)
            credits_used = 0
            if generated_now:
                allowed, _reason = can_use_ai_for_cost(wa_phone, VOICE_CACHED_FIRST_GEN_COST)
                if not allowed:
                    return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "cache", "voice": "blocked"}}
                credits_used = VOICE_CACHED_FIRST_GEN_COST
                ledger_add(wa_phone, -credits_used, "tts_cached_gen")
            return {"ok": True, "answer_text": formatted, "audio_url": audio_url, "credits_used": credits_used, "meta": {"source": "cache"}}

        return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "cache"}}

    # 3) AI fallback
    credits_needed = VOICE_AI_COST if mode == "voice" else TEXT_AI_COST
    allowed, reason = can_use_ai_for_cost(wa_phone, credits_needed)
    if not allowed:
        daily_total_usage_inc(wa_phone, 1)
        ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=0)
        msg = (reason or "Please subscribe to continue.") + "\n\nPlease subscribe to continue asking questions."
        formatted = format_markdown_answer(question, msg)
        return {"ok": True, "answer_text": formatted, "audio_url": None, "credits_used": 0, "meta": {"source": "ai_blocked"}}

    ans_raw = ai_answer_text(question, lang=lang)
    ans = format_markdown_answer(question, ans_raw)
    cache_set(question, ans)

    ledger_add(wa_phone, -credits_needed, "ai_voice" if mode == "voice" else "ai_text")

    daily_total_usage_inc(wa_phone, 1)
    ai_daily_usage_inc(wa_phone, total_inc=1, ai_inc=1)

    if mode == "voice":
        audio_url, _ = ensure_voice_for_text(nq, ans, voice_provider, voice_style)
        return {"ok": True, "answer_text": ans, "audio_url": audio_url, "credits_used": credits_needed, "meta": {"source": "ai"}}

    return {"ok": True, "answer_text": ans, "audio_url": None, "credits_used": credits_needed, "meta": {"source": "ai"}}
