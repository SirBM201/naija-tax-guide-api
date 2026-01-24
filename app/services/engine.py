# app/services/engine.py
import logging
from typing import Dict, Any

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question


def resolve_answer(
    wa_phone: str,
    question: str,
    mode: str = "text",
    lang: str = "en",
    source: str = "web",
) -> Dict[str, Any]:
    """
    Resolution order:
    1) qa_cache (by normalized_question)
    2) qa_library (by normalized_question + lang)
    3) fallback message
    """
    q_raw = (question or "").strip()
    q_norm = normalize_question(q_raw)

    logging.info("ENGINE source=%s wa_phone=%s lang=%s mode=%s raw=%s norm=%s",
                 source, wa_phone, lang, mode, q_raw[:120], q_norm[:120])

    # 1) Cache
    try:
        cached = cache_get(q_norm)  # IMPORTANT: normalized
    except Exception as e:
        logging.exception("cache_get failed (continuing without cache): %s", e)
        cached = None

    if cached and cached.get("answer"):
        return {"ok": True, "answer_text": cached["answer"], "source": "cache"}

    # 2) Library
    try:
        lib = library_get(q_norm, lang=lang)  # IMPORTANT: normalized
    except Exception as e:
        logging.exception("library_get failed: %s", e)
        lib = None

    if lib and lib.get("answer"):
        ans = lib["answer"]

        # write-through cache
        try:
            cache_put(q_norm, ans, tags=["library"], source=source)  # IMPORTANT: normalized
        except Exception as e:
            logging.exception("cache_put failed (ignored): %s", e)

        return {"ok": True, "answer_text": ans, "source": "library"}

    # 3) Fallback
    return {
        "ok": True,
        "answer_text": "I can help. Please ask your tax question (e.g., VAT, PAYE, TIN, filing, penalties).",
        "source": "fallback",
    }
