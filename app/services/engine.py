import logging
from typing import Dict, Any

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question

from app.services.ai import generate_answer
from app.services.ai_policy import can_use_ai, consume_ai, log_ai_cost
from app.services.reviewer import review_answer


def _db():
    from app.db.supabase_client import supabase as get_supabase
    return get_supabase()


def _insert_suggestion(q_norm: str, q_raw: str, lang: str, answer: str, source: str, review: Dict[str, Any]) -> None:
    """
    Table: qa_suggestions exists in your DB.
    This is best-effort; schema mismatches won't break the app.
    """
    try:
        _db().table("qa_suggestions").insert(
            {
                "normalized_question": q_norm,
                "question_raw": q_raw[:500],
                "lang": lang,
                "answer": answer[:4000],
                "source": source,
                "needs_review": True,
                "risk": review.get("risk"),
                "confidence": review.get("confidence"),
                "reasons": str(review.get("reasons") or [])[:1000],
            }
        ).execute()
    except Exception as e:
        logging.exception("qa_suggestions insert failed (ignored): %s", e)


def _auto_promote_to_library(q_norm: str, lang: str, answer: str) -> bool:
    """
    Best-effort upsert to qa_library.
    Assumes qa_library has at least: normalized_question, lang, answer
    If your unique constraint differs, failure is ignored and returns False.
    """
    try:
        _db().table("qa_library").upsert(
            {
                "normalized_question": q_norm,
                "lang": lang,
                "answer": answer,
                "status": "active",  # if your table doesn't have this column, it will be ignored only if supabase allows; if not, remove it.
            },
            on_conflict="normalized_question,lang",
        ).execute()
        return True
    except Exception as e:
        logging.exception("qa_library auto-promote failed (ignored): %s", e)
        # retry without 'status' in case that column doesn't exist
        try:
            _db().table("qa_library").upsert(
                {"normalized_question": q_norm, "lang": lang, "answer": answer},
                on_conflict="normalized_question,lang",
            ).execute()
            return True
        except Exception as e2:
            logging.exception("qa_library auto-promote retry failed (ignored): %s", e2)
            return False


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
        "ENGINE source=%s wa_phone=%s lang=%s mode=%s raw=%s norm=%s",
        source, wa_phone, lang, mode, q_raw[:120], q_norm[:120]
    )

    # 1) Cache
    try:
        cached = cache_get(q_norm)
    except Exception as e:
        logging.exception("cache_get failed (continuing without cache): %s", e)
        cached = None

    if cached and cached.get("answer"):
        return {"ok": True, "answer_text": cached["answer"], "source": "cache"}

    # 2) Library
    try:
        lib = library_get(q_norm, lang=lang)
    except Exception as e:
        logging.exception("library_get failed: %s", e)
        lib = None

    if lib and lib.get("answer"):
        ans = lib["answer"]
        try:
            cache_put(q_norm, ans, tags=["library"], source=source)
        except Exception as e:
            logging.exception("cache_put failed (ignored): %s", e)
        return {"ok": True, "answer_text": ans, "source": "library"}

    # 3) AI fallback (enforce plan limits)
    quota = can_use_ai(wa_phone)
    if not quota.get("ok"):
        action = quota.get("action")
        if action == "topup":
            msg = "Your AI credits for this plan are finished. Please top up to continue."
        else:
            msg = "You have used your free AI limit for today (2/day). Please upgrade to continue."
        return {"ok": False, "message": msg, "reason": quota.get("reason")}

    ai_text = generate_answer(q_raw, lang=lang)
    if not ai_text:
        return {
            "ok": True,
            "answer_text": "I can help. Please ask your Nigeria tax question (e.g., VAT, PAYE, TIN, filing, penalties).",
            "source": "fallback",
        }

    # consume usage only after AI success
    try:
        consume_ai(wa_phone, quota.get("plan", "free"), quota.get("mode", "free_daily"))
    except Exception as e:
        logging.exception("consume_ai failed (ignored): %s", e)

    # cache write-through
    try:
        cache_put(q_norm, ai_text, tags=["ai"], source=source)
    except Exception as e:
        logging.exception("cache_put(ai) failed (ignored): %s", e)

    # cost tracking
    try:
        log_ai_cost(wa_phone, q_raw, ai_text, source="ai")
    except Exception as e:
        logging.exception("log_ai_cost failed (ignored): %s", e)

    # 4) Risk scorer review (reduces admin work)
    review = review_answer(q_raw, ai_text, lang=lang)

    auto_promoted = False
    if review.get("ok") and review.get("auto_promote_ok"):
        auto_promoted = _auto_promote_to_library(q_norm, lang, ai_text)

    if not auto_promoted:
        _insert_suggestion(q_norm, q_raw, lang, ai_text, source, review)

    return {
        "ok": True,
        "answer_text": ai_text,
        "source": "ai",
        "review": {
            "risk": review.get("risk"),
            "confidence": review.get("confidence"),
            "auto_promoted": auto_promoted,
        },
    }
