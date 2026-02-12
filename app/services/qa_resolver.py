# app/services/qa_resolver.py
from __future__ import annotations
from typing import Dict, Any, Optional, Callable

from .lang_service import normalize_lang, detect_lang
from .text_keys import canonicalize_question
from .qa_library_service import get_library_answer_by_canonical
from .qa_cache_service import get_cache_answer, upsert_cache_ai_answer

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
        used_ai: bool
      }
    """
    q = (question or "").strip()
    if not q:
        return {"ok": False, "error": "empty_question"}

    resolved_lang = normalize_lang(lang) if lang else detect_lang(q)
    canonical_key = canonicalize_question(q, lang=resolved_lang)

    # 1) qa_library
    lib = get_library_answer_by_canonical(canonical_key, resolved_lang)
    if lib and lib.get("answer"):
        return {
            "ok": True,
            "answer": lib["answer"],
            "source": "library",
            "lang": lib.get("lang_used") or resolved_lang,
            "canonical_key": lib.get("canonical_key") or canonical_key,
            "used_ai": False,
        }

    # 2) qa_cache
    cached = get_cache_answer(canonical_key, resolved_lang)
    if cached and cached.get("answer"):
        return {
            "ok": True,
            "answer": cached["answer"],
            "source": "cache",
            "lang": cached.get("lang_used") or resolved_lang,
            "canonical_key": cached.get("canonical_key") or canonical_key,
            "used_ai": False,
        }

    # 3) AI
    if not ai_generate:
        return {"ok": False, "error": "ai_generate_not_configured", "canonical_key": canonical_key}

    ans = ai_generate(q, resolved_lang, channel)
    ans = (ans or "").strip()
    if not ans:
        return {"ok": False, "error": "ai_empty_answer", "canonical_key": canonical_key}

    # Save ONLY AI answer into qa_cache (your rule)
    upsert_cache_ai_answer(canonical_key=canonical_key, lang=resolved_lang, answer=ans, tags=tags, priority=0)

    return {
        "ok": True,
        "answer": ans,
        "source": "ai",
        "lang": resolved_lang,
        "canonical_key": canonical_key,
        "used_ai": True,
    }
