from __future__ import annotations
from typing import Dict, Any, Optional, Callable

from .lang_service import normalize_lang, detect_lang
from .text_keys import canonicalize_question
from .qa_aliases_service import find_canonical_by_alias
from .qa_library_service import get_library_answer_by_canonical
from .qa_cache_service import (
    get_cache_answer,
    get_cache_answer_en_fallback,
    upsert_cache_ai_answer,
)
from .translation_jobs_service import enqueue_translation_job

def resolve_answer(
    *,
    question: str,
    lang: Optional[str] = None,
    channel: str = "web",
    ai_generate: Optional[Callable[[str, str, str], str]] = None,
    tags=None,
) -> Dict[str, Any]:
    """
    Returns:
      {
        ok: bool,
        answer: str,
        source: 'library'|'cache'|'ai',
        lang: lang_used,
        canonical_key: str,
        used_ai: bool,
        matched_via: 'direct'|'alias'
      }
    """
    q = (question or "").strip()
    if not q:
        return {"ok": False, "error": "empty_question"}

    # 1) Resolve language (cheap, offline)
    resolved_lang = normalize_lang(lang) if lang else detect_lang(q)

    # 2) Build alias_key from the user's exact input in that language
    alias_key = canonicalize_question(q, lang=resolved_lang)

    # 3) Try map alias_key -> canonical_key (lets Yoruba/Igbo/Hausa/Pidgin map to EN canonical)
    canonical_key = find_canonical_by_alias(alias_key, resolved_lang)
    matched_via = "alias" if canonical_key else "direct"

    # 4) If no alias mapping, fallback to direct canonicalization (works for English)
    if not canonical_key:
        canonical_key = canonicalize_question(q, lang="en")  # normalize as EN intent
        matched_via = "direct"

    if not canonical_key:
        return {"ok": False, "error": "canonical_key_empty"}

    # -----------------------------
    # RANKING ORDER (FIXED)
    # -----------------------------

    # A) qa_library exact canonical
    lib = get_library_answer_by_canonical(canonical_key, resolved_lang)
    if lib and lib.get("answer"):
        return {
            "ok": True,
            "answer": lib["answer"],
            "source": "library",
            "lang": lib.get("lang_used") or resolved_lang,
            "canonical_key": canonical_key,
            "used_ai": False,
            "matched_via": matched_via,
        }

    # B) qa_cache exact canonical + requested lang
    cached = get_cache_answer(canonical_key, resolved_lang)
    if cached and cached.get("answer"):
        return {
            "ok": True,
            "answer": cached["answer"],
            "source": "cache",
            "lang": cached.get("lang_used") or resolved_lang,
            "canonical_key": canonical_key,
            "used_ai": False,
            "matched_via": matched_via,
        }

    # C) qa_cache English fallback (ONLY if requested lang missing)
    if resolved_lang != "en":
        cached_en = get_cache_answer_en_fallback(canonical_key)
        if cached_en and cached_en.get("answer"):
            # enqueue offline translation so next time Yoruba gets Yoruba (no extra runtime cost)
            enqueue_translation_job(
                canonical_key=canonical_key,
                kind="answer",
                target_lang=resolved_lang,
                source_table="qa_cache",
                source_lang="en",
            )
            return {
                "ok": True,
                "answer": cached_en["answer"],
                "source": "cache",
                "lang": "en",
                "canonical_key": canonical_key,
                "used_ai": False,
                "matched_via": matched_via,
                "note": "served_en_fallback_translation_queued",
            }

    # D) AI generate (must answer in resolved_lang)
    if not ai_generate:
        return {"ok": False, "error": "ai_generate_not_configured", "canonical_key": canonical_key}

    ans = (ai_generate(q, resolved_lang, channel) or "").strip()
    if not ans:
        return {"ok": False, "error": "ai_empty_answer", "canonical_key": canonical_key}

    # Save ONLY AI answers into qa_cache (your rule)
    upsert_cache_ai_answer(canonical_key=canonical_key, lang=resolved_lang, answer=ans, tags=tags, priority=0)

    return {
        "ok": True,
        "answer": ans,
        "source": "ai",
        "lang": resolved_lang,
        "canonical_key": canonical_key,
        "used_ai": True,
        "matched_via": matched_via,
    }
