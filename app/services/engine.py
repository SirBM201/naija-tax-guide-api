import logging
from typing import Dict, Any

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question
from app.services.ai import generate_answer


def _is_valid_answer(ans: str) -> bool:
    if not ans:
        return False
    bad = [
        "please ask your tax question",
        "i can help",
    ]
    a = ans.strip().lower()
    return not any(b in a for b in bad)


def resolve_answer(
    wa_phone: str,
    question: str,
    mode: str = "text",
    lang: str = "en",
    source: str = "web",
) -> Dict[str, Any]:
    q_raw = (question or "").strip()
    q_norm = normalize_question(q_raw)

    logging.info(
        "ENGINE source=%s wa_phone=%s lang=%s raw=%s norm=%s",
        source,
        wa_phone,
        lang,
        q_raw[:120],
        q_norm[:120],
    )

    # 1) CACHE
    try:
        cached = cache_get(q_norm)
        if cached and _is_valid_answer(cached.get("answer")):
            return {
                "ok": True,
                "answer_text": cached["answer"],
                "source": "cache",
            }
    except Exception as e:
        logging.exception("cache_get failed: %s", e)

    # 2) LIBRARY
    try:
        lib = library_get(q_norm, lang=lang)
        if lib and _is_valid_answer(lib.get("answer")):
            ans = lib["answer"]

            try:
                cache_put(q_norm, ans, tags=["library"], source=source)
            except Exception:
                pass

            return {
                "ok": True,
                "answer_text": ans,
                "source": "library",
            }
    except Exception as e:
        logging.exception("library_get failed: %s", e)

    # 3) AI FALLBACK (FINAL GUARANTEE)
    logging.info("ENGINE → AI fallback triggered")

    ai_answer = generate_answer(question=q_raw, lang=lang)

    if ai_answer:
        try:
            cache_put(q_norm, ai_answer, tags=["ai"], source=source)
        except Exception:
            pass

        return {
            "ok": True,
            "answer_text": ai_answer,
            "source": "ai",
        }

    # Absolute last fallback (should almost never happen)
    return {
        "ok": True,
        "answer_text": "Unable to generate an answer at the moment. Please try again.",
        "source": "fallback",
    }
