import logging
from typing import Dict, Any

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question
from app.services.ai import generate_answer


def resolve_answer(
    wa_phone: str,
    question: str,
    mode: str = "text",
    lang: str = "en",
    source: str = "web",
) -> Dict[str, Any]:
    """
    Resolution order:
    1) qa_cache (normalized_question)
    2) qa_library (normalized_question + lang)
    3) AI fallback (auto-saved to cache)
    """

    # ---------------------------
    # Normalize question
    # ---------------------------
    q_raw = (question or "").strip()
    q_norm = normalize_question(q_raw)

    logging.info(
        "ENGINE source=%s wa_phone=%s lang=%s mode=%s raw=%s norm=%s",
        source,
        wa_phone,
        lang,
        mode,
        q_raw[:120],
        q_norm[:120],
    )

    # ---------------------------
    # Question header (A + B)
    # ---------------------------
    question_header = f"\n\n---\n\n**{q_raw.upper()}**\n\n"

    # ---------------------------
    # 1) CACHE
    # ---------------------------
    try:
        cached = cache_get(q_norm)
    except Exception as e:
        logging.exception("cache_get failed: %s", e)
        cached = None

    if cached and cached.get("answer"):
        return {
            "ok": True,
            "answer_text": question_header + cached["answer"],
            "source": "cache",
        }

    # ---------------------------
    # 2) LIBRARY
    # ---------------------------
    try:
        lib = library_get(q_norm, lang=lang)
    except Exception as e:
        logging.exception("library_get failed: %s", e)
        lib = None

    if lib and lib.get("answer"):
        answer = lib["answer"]

        # Write-through cache
        try:
            cache_put(
                q_norm,
                answer,
                tags=["library"],
                source=source,
            )
        except Exception as e:
            logging.exception("cache_put (library) failed: %s", e)

        return {
            "ok": True,
            "answer_text": question_header + answer,
            "source": "library",
        }

    # ---------------------------
    # 3) AI FALLBACK (AUTO-SAVE)
    # ---------------------------
    try:
        ai_answer = generate_answer(
            question=q_raw,
            lang=lang,
        )

        if ai_answer:
            try:
                cache_put(
                    q_norm,
                    ai_answer,
                    tags=["ai"],
                    source=source,
                )
            except Exception as e:
                logging.exception("cache_put (ai) failed: %s", e)

            return {
                "ok": True,
                "answer_text": question_header + ai_answer,
                "source": "ai",
            }

    except Exception as e:
        logging.exception("AI generation failed: %s", e)

    # ---------------------------
    # FINAL SAFE FALLBACK
    # ---------------------------
    return {
        "ok": True,
        "answer_text": question_header
        + "I can help. Please ask your tax question "
          "(e.g., VAT, PAYE, TIN, filing, penalties).",
        "source": "fallback",
    }
