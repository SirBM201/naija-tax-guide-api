import logging
from typing import Dict, Any

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question
from app.services.ai import generate_answer   # ← AI fallback


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
    3) AI fallback (auto-save to cache)
    """

    q_raw = (question or "").strip()
    q_norm = normalize_question(q_raw)

    logging.info(
        "ENGINE source=%s wa_phone=%s lang=%s mode=%s raw=%s norm=%s",
        source, wa_phone, lang, mode, q_raw[:120], q_norm[:120]
    )

    # --------------------------------------------------
    # 1) CACHE
    # --------------------------------------------------
    try:
        cached = cache_get(q_norm)
    except Exception as e:
        logging.exception("cache_get failed (continuing): %s", e)
        cached = None

    if cached and cached.get("answer"):
        return {
            "ok": True,
            "answer_text": cached["answer"],
            "source": "cache",
        }

    # --------------------------------------------------
    # 2) LIBRARY
    # --------------------------------------------------
    try:
        lib = library_get(q_norm, lang=lang)
    except Exception as e:
        logging.exception("library_get failed: %s", e)
        lib = None

    if lib and lib.get("answer"):
        ans = lib["answer"]

        # write-through cache
        try:
            cache_put(
                normalized_question=q_norm,
                answer=ans,
                tags=["library"],
                source=source,
            )
        except Exception as e:
            logging.exception("cache_put (library) failed: %s", e)

        return {
            "ok": True,
            "answer_text": ans,
            "source": "library",
        }

    # --------------------------------------------------
    # 3) AI FALLBACK (FINAL FIX)
    # --------------------------------------------------
    try:
        logging.info("AI fallback triggered for: %s", q_norm)

        ai_answer = generate_answer(
            question=q_raw,
            lang=lang,
            context="Nigeria tax guidance",
        )

        if not ai_answer:
            raise RuntimeError("AI returned empty response")

        # Auto-save to cache for future use
        try:
            cache_put(
                normalized_question=q_norm,
                answer=ai_answer,
                tags=["ai"],
                source=source,
            )
        except Exception as e:
            logging.exception("cache_put (ai) failed: %s", e)

        return {
            "ok": True,
            "answer_text": ai_answer,
            "source": "ai",
        }

    except Exception as e:
        logging.exception("AI fallback failed: %s", e)

        return {
            "ok": False,
            "error": "Unable to generate an answer at this time.",
        }
