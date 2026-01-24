import logging
from typing import Dict, Any

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question

log = logging.getLogger(__name__)

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
    3) fallback
    """
    q = (question or "").strip()
    normalized_q = normalize_question(q)

    # 1) Cache (fail-safe)
    cached = cache_get(q)
    if cached and cached.get("answer"):
        return {"ok": True, "answer_text": cached["answer"], "source": "cache"}

    # 2) Library (fail-safe)
    lib = library_get(normalized_q, lang=lang)
    if lib and lib.get("answer"):
        ans = lib["answer"]
        cache_put(q, ans, tags=["library"], source=source)  # write-through cache (fail-safe)
        return {"ok": True, "answer_text": ans, "source": "library"}

    # 3) Fallback
    return {
        "ok": True,
        "answer_text": "I can help. Please ask your tax question (e.g., VAT, PAYE, TIN, filing, penalties).",
        "source": "fallback",
    }
