# app/services/engine.py
import logging
from typing import Dict, Any, List

from app.db.qa import cache_get, cache_put, library_get
from app.core.text import normalize_question

from app.services.ai import generate_answer
from app.services.ai_policy import can_use_ai, consume_ai, log_ai_cost
from app.services.reviewer import review_answer

from app.db.supabase_client import supabase


def _pick_answer_columns(lang: str) -> List[str]:
    l = (lang or "en").strip().lower()
    mapping = {
        "en": ["answer_en", "answer"],
        "pcm": ["answer_pcm", "answer_pidgin", "answer_pigdin", "answer"],
        "yo": ["answer_yo", "answer_yoruba", "answer"],
        "ig": ["answer_ig", "answer_igbo", "answer"],
        "ha": ["answer_ha", "answer_hausa", "answer"],
    }
    return mapping.get(l, ["answer_en", "answer"])


def _insert_suggestion(q_norm: str, q_raw: str, lang: str, answer: str, source: str, review: Dict[str, Any]) -> None:
    try:
        supabase().table("qa_suggestions").insert(
            {
                "normalized_question": q_norm,
                "question_raw": (q_raw or "")[:500],
                "lang": (lang or "en")[:10],
                "answer": (answer or "")[:4000],
                "source": (source or "")[:30],
                "needs_review": True,
                "risk": review.get("risk"),
                "confidence": review.get("confidence"),
                "reasons": str(review.get("reasons") or [])[:1000],
            }
        ).execute()
    except Exception as e:
        logging.exception("qa_suggestions insert failed (ignored): %s", e)


def _auto_promote_to_library(q_norm: str, q_raw: str, lang: str, answer: str) -> bool:
    cols_to_try = _pick_answer_columns(lang)

    base_payload = {
        "normalized_question": q_norm,
        "question": (q_raw or "")[:500],
        "enabled": True,
        "source": "auto_ai",
        "priority": 50,
    }

    for ans_col in cols_to_try:
        payload = dict(base_payload)
        payload[ans_col] = answer

        try:
            supabase().table("qa_library").upsert(payload, on_conflict="normalized_question").execute()
            return True
        except Exception as e:
            logging.exception("qa_library auto-promote failed using %s (ignored): %s", ans_col, e)

            # retry minimal
            try:
                minimal = {"normalized_question": q_norm, ans_col: answer}
                supabase().table("qa_library").upsert(minimal, on_conflict="normalized_question").execute()
                return True
            except Exception as e2:
                logging.exception("qa_library auto-promote retry failed using %s (ignored): %s", ans_col, e2)

    return False


def resolve_answer(
    wa_phone: str,
    question: str,
    mode: str = "text",
    lang: str = "en",
    source: str = "web",
) -> Dict[str, Any]:
    identity = (wa_phone or "").strip()  # IMPORTANT: this is your unified identity string (acct:<uuid>)
    q_raw = (question or "").strip()
    q_norm = normalize_question(q_raw)

    logging.info(
        "ENGINE source=%s identity=%s lang=%s mode=%s raw=%s norm=%s",
        source, identity, lang, mode, q_raw[:120], q_norm[:120]
    )

    # 1) Cache
    cached = None
    try:
        cached = cache_get(q_norm)
    except Exception as e:
        logging.exception("cache_get failed (continuing without cache): %s", e)

    if cached and cached.get("answer"):
        return {"ok": True, "answer_text": cached["answer"], "source": "cache"}

    # 2) Library
    lib = None
    try:
        lib = library_get(q_norm, lang=lang)
    except Exception as e:
        logging.exception("library_get failed: %s", e)

    if lib and lib.get("answer"):
        ans = lib["answer"]
        try:
            cache_put(q_norm, ans, tags=["library"], source=source)
        except Exception as e:
            logging.exception("cache_put failed (ignored): %s", e)
        return {"ok": True, "answer_text": ans, "source": "library"}

    # 3) AI fallback (quota enforced)
    quota = can_use_ai(identity)
    if not quota.get("ok"):
        action = quota.get("action")
        if action == "topup":
            msg = "Your AI credits are finished. Please top up to continue."
        else:
            msg = "You have used your free AI limit for today (2/day). Please upgrade to continue."
        return {"ok": False, "message": msg, "reason": quota.get("reason"), "action": action}

    ai_text = generate_answer(q_raw, lang=lang)
    if not ai_text:
        return {
            "ok": True,
            "answer_text": "I can help. Please ask your Nigeria tax question (e.g., VAT, PAYE, TIN, filing, penalties).",
            "source": "fallback",
        }

    # consume usage only after AI success
    try:
        consume_ai(
            identity,
            quota.get("plan", "free"),
            quota.get("mode", "free_daily"),
            period_end=quota.get("period_end"),
        )
    except Exception as e:
        logging.exception("consume_ai failed (ignored): %s", e)

    # cache write-through
    try:
        cache_put(q_norm, ai_text, tags=["ai"], source=source)
    except Exception as e:
        logging.exception("cache_put(ai) failed (ignored): %s", e)

    # cost tracking
    try:
        log_ai_cost(identity, q_raw, ai_text, source="ai")
    except Exception as e:
        logging.exception("log_ai_cost failed (ignored): %s", e)

    # 4) Risk review
    review = review_answer(q_raw, ai_text, lang=lang)

    auto_promoted = False
    if review.get("ok") and review.get("auto_promote_ok"):
        auto_promoted = _auto_promote_to_library(q_norm, q_raw, lang, ai_text)

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
