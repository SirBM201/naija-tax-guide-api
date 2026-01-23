# app/services/engine.py
import logging
from typing import Dict, Any, Optional

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question  # align if your normalize is elsewhere

def resolve_answer(
    wa_phone: str,
    question: str,
    mode: str = "text",
    lang: str = "en",
    source: str = "web",
) -> Dict[str, Any]:
    """
    Resolution order:
    1) qa_cache
    2) qa_library
    3) fallback message (or AI later)
    """
    q = (question or "").strip()
    normalized_q = normalize_question(q)

    # 1) Cache (fail-safe)
    cached = None
    try:
        cached = cache_get(q)
    except Exception as e:
        logging.exception("cache_get failed (continuing without cache): %s", e)
        cached = None

    if cached and cached.get("answer"):
        return {
            "ok": True,
            "answer_text": cached["answer"],
            "source": "cache",
        }

    # 2) Library
    lib = None
    try:
        lib = library_get(normalized_q, lang=lang)
    except Exception as e:
        logging.exception("library_get failed: %s", e)
        lib = None

    if lib and lib.get("answer"):
        ans = lib["answer"]

        # write-through cache (fail-safe)
        try:
            cache_put(q, ans, tags=["library"], source=source)
        except Exception as e:
            logging.exception("cache_put failed (ignored): %s", e)

        return {
            "ok": True,
            "answer_text": ans,
            "source": "library",
        }

    # 3) Fallback (AI later)
    return {
        "ok": True,
        "answer_text": "I can help. Please ask your tax question (e.g., VAT, PAYE, TIN, filing, penalties).",
        "source": "fallback",
    }
