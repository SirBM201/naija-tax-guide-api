# app/services/qa_resolver.py
from __future__ import annotations

from typing import Dict, Any, Optional, Callable

from .lang_service import normalize_lang, detect_lang
from .text_keys import canonicalize_question
from .qa_library_service import get_library_answer_by_canonical
from .qa_cache_service import get_cache_answer, upsert_cache_ai_answer
from .qa_aliases_service import resolve_alias_to_canonical
from .translation_jobs_service import enqueue_missing_translations


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
        fallback_used: bool
      }
    """
    q = (question or "").strip()
    if not q:
        return {"ok": False, "error": "empty_question"}

    requested_lang = normalize_lang(lang) if lang else detect_lang(q)

    # 1) Compute alias_key for the user's language
    #    NOTE: canonicalize_question here is used to make a stable key for the exact language text.
    alias_key = canonicalize_question(q, lang=requested_lang)

    # 2) Map alias -> canonical_key (EN canonical)
    #    If not found:
    #      - if english, canonical_key = alias_key (since alias_key is already EN-ish)
    #      - else we will still use alias_key as a temporary canonical, but English fallback will likely fail.
    canonical_key = resolve_alias_to_canonical(alias_key=alias_key, lang=requested_lang) or (
        alias_key if requested_lang == "en" else alias_key
    )

    # Helper: try (table, lang) then return normalized payload
    def _try_sources(lang_to_use: str) -> Optional[Dict[str, Any]]:
        lib = get_library_answer_by_canonical(canonical_key, lang_to_use)
        if lib and lib.get("answer"):
            return {
                "ok": True,
                "answer": lib["answer"],
                "source": "library",
                "lang": lib.get("lang_used") or lang_to_use,
                "canonical_key": lib.get("canonical_key") or canonical_key,
                "used_ai": False,
                "fallback_used": (lang_to_use != requested_lang),
            }

        cached = get_cache_answer(canonical_key, lang_to_use)
        if cached and cached.get("answer"):
            return {
                "ok": True,
                "answer": cached["answer"],
                "source": "cache",
                "lang": cached.get("lang_used") or lang_to_use,
                "canonical_key": cached.get("canonical_key") or canonical_key,
                "used_ai": False,
                "fallback_used": (lang_to_use != requested_lang),
            }

        return None

    # 3) First: requested language
    hit = _try_sources(requested_lang)
    if hit:
        return hit

    # 4) Fallback: English (VERY important for cost control)
    hit = _try_sources("en")
    if hit:
        # enqueue translations for next time (offline job)
        enqueue_missing_translations(canonical_key=canonical_key, target_lang=requested_lang)
        return hit

    # 5) AI (last resort)
    if not ai_generate:
        return {"ok": False, "error": "ai_generate_not_configured", "canonical_key": canonical_key}

    ans = (ai_generate(q, requested_lang, channel) or "").strip()
    if not ans:
        return {"ok": False, "error": "ai_empty_answer", "canonical_key": canonical_key}

    # Save AI answer into qa_cache
    upsert_cache_ai_answer(
        canonical_key=canonical_key,
        lang=requested_lang,
        answer=ans,
        tags=tags,
        priority=0,
    )

    # Also enqueue EN + other translations if you want to spread coverage
    enqueue_missing_translations(canonical_key=canonical_key, target_lang=requested_lang)

    return {
        "ok": True,
        "answer": ans,
        "source": "ai",
        "lang": requested_lang,
        "canonical_key": canonical_key,
        "used_ai": True,
        "fallback_used": False,
    }
