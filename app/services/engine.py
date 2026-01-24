import logging
from typing import Dict, Any

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question

from app.services.ai import generate_answer
from app.services.ai_policy import can_use_ai, consume_ai, log_ai_cost


def _suggest_for_admin(q_norm: str, q_raw: str, lang: str, answer: str, source: str) -> None:
    """
    Creates a candidate record for admin review (best effort).
    Table in your DB: qa_suggestions (exists in your screenshots).
    If your columns differ, it will not break anything.
    """
    try:
        # local import to avoid boot errors if table/columns mismatch
        from app.db.supabase_client import supabase

        supabase.table("qa_suggestions").insert(
            {
                "normalized_question": q_norm,
                "question_raw": q_raw[:500],
                "lang": lang,
                "answer": answer[:4000],
                "source": source,
                "needs_review": True,
                "created_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            }
        ).execute()
    except Exception as e:
        logging.exception("qa_suggestions insert failed (ignored): %s", e)


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
    3) AI fallback (respects plan limits)
       - writes-through qa_cache
       - creates qa_suggestions row for admin review (Option 1)
    """
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

    # 3) AI fallback (Option 1: user gets answer now; admin reviews for library later)
    quota = can_use_ai(wa_phone)
    if not quota.get("ok"):
        # consistent, platform-agnostic block message
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

    # consume usage only when AI succeeds
    try:
        consume_ai(wa_phone, quota.get("plan", "free"), quota.get("mode", "free_daily"))
    except Exception as e:
        logging.exception("consume_ai failed (ignored): %s", e)

    # write-through cache for future speed (Option 1)
    try:
        cache_put(q_norm, ai_text, tags=["ai"], source=source)
    except Exception as e:
        logging.exception("cache_put(ai) failed (ignored): %s", e)

    # admin candidate record (best effort)
    _suggest_for_admin(q_norm=q_norm, q_raw=q_raw, lang=lang, answer=ai_text, source=source)

    # cost tracking (best effort)
    try:
        log_ai_cost(wa_phone, q_raw, ai_text, source="ai")
    except Exception as e:
        logging.exception("log_ai_cost failed (ignored): %s", e)

    return {"ok": True, "answer_text": ai_text, "source": "ai"}
