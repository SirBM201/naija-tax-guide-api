# app/services/response_refiner.py
from __future__ import annotations

from typing import Any, Dict, Optional


TRUST_THRESHOLD = 0.75
CONFIDENCE_THRESHOLD = 0.72
AUTHORITY_THRESHOLD = 0.60


def _normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _same(a: Any, b: Any) -> bool:
    return _normalize(a) == _normalize(b)


def looks_like_ai_failure(text: str) -> bool:
    t = _normalize(text)
    if not t:
        return True

    bad_patterns = [
        "ai temporarily unavailable",
        "ai service not configured",
        "openai_api_key not set",
        "invalid_api_key",
        "incorrect api key",
        "quota",
        "rate limit",
        "request timed out",
        "no answer generated",
        "openai import failed",
        "client init failed",
        "something went wrong",
        "unauthorized",
        "401",
        "ai_not_configured",
        "openai_call_failed",
        "openai_empty_answer",
        "openai_sdk_missing",
    ]
    return any(p in t for p in bad_patterns)


def refine_response(
    *,
    question_meta: Dict[str, Any],
    candidate: Optional[Dict[str, Any]],
    grounded_result: Optional[Dict[str, Any]],
    credits_available: bool,
) -> Dict[str, Any]:
    """
    Final validation layer before the answer leaves the backend.

    This blocks:
    - unapproved answers
    - low trust answers
    - topic mismatch
    - intent mismatch
    - jurisdiction mismatch
    - low-confidence grounded answers
    - weak/no-credit uncached fallbacks
    """

    if not candidate:
        return {
            "allowed": False,
            "decision": "no_candidate",
            "reason": "no_candidate",
            "user_message": (
                "I could not find a sufficiently reliable answer for that question yet."
            ),
        }

    review_status = _normalize(candidate.get("review_status") or "approved")
    trust_score = _float(candidate.get("trust_score"), 1.0)
    candidate_topic = candidate.get("topic")
    candidate_intent = candidate.get("intent_type")
    candidate_jurisdiction = candidate.get("jurisdiction") or "nigeria"

    question_topic = question_meta.get("topic")
    question_intent = question_meta.get("intent_type")
    question_jurisdiction = question_meta.get("jurisdiction") or "nigeria"

    if review_status != "approved":
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "unapproved_answer",
            "user_message": (
                "That answer is not yet approved for reliable use."
            ),
        }

    if trust_score < TRUST_THRESHOLD:
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "low_trust",
            "user_message": (
                "I found a related answer, but it is not trusted enough to return safely."
            ),
        }

    if question_topic and candidate_topic and not _same(candidate_topic, question_topic):
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "topic_mismatch",
            "user_message": (
                "I found related material, but it does not match your exact tax topic closely enough."
            ),
        }

    if question_intent and candidate_intent and not _same(candidate_intent, question_intent):
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "intent_mismatch",
            "user_message": (
                "I found related material, but it does not match the type of answer your question requires."
            ),
        }

    if not _same(candidate_jurisdiction, question_jurisdiction):
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "jurisdiction_mismatch",
            "user_message": (
                "I found related material, but it is not aligned with Nigerian tax context."
            ),
        }

    if not grounded_result:
        if credits_available:
            return {
                "allowed": False,
                "decision": "needs_grounding",
                "reason": "missing_grounding",
                "user_message": (
                    "I need to ground this answer more carefully before returning it."
                ),
            }

        return {
            "allowed": False,
            "decision": "insufficient_credits_uncached",
            "reason": "missing_grounding_and_no_credits",
            "user_message": (
                "Your available AI usage for this period is exhausted, and I do not have a sufficiently grounded cached answer for this question yet."
            ),
        }

    grounded = bool(grounded_result.get("grounded"))
    confidence = _float(grounded_result.get("confidence"))
    authority_score = _float(grounded_result.get("authority_score"))
    jurisdiction_ok = bool(grounded_result.get("jurisdiction_ok"))
    topic_ok = bool(grounded_result.get("topic_ok"))
    intent_ok = bool(grounded_result.get("intent_ok"))

    if not grounded:
        if credits_available:
            return {
                "allowed": False,
                "decision": "needs_better_grounding",
                "reason": grounded_result.get("refusal_reason") or "grounding_failed",
                "user_message": (
                    "I found related material, but it is not grounded strongly enough for a safe answer yet."
                ),
            }

        return {
            "allowed": False,
            "decision": "insufficient_credits_uncached",
            "reason": grounded_result.get("refusal_reason") or "grounding_failed_no_credits",
            "user_message": (
                "Your available AI usage for this period is exhausted, and I do not have a sufficiently reliable cached answer for this question yet."
            ),
        }

    if not jurisdiction_ok or not topic_ok or not intent_ok:
        if credits_available:
            return {
                "allowed": False,
                "decision": "needs_grounded_synthesis",
                "reason": "compatibility_failed",
                "user_message": (
                    "I need a better-grounded synthesis for this question before answering."
                ),
            }

        return {
            "allowed": False,
            "decision": "insufficient_credits_uncached",
            "reason": "compatibility_failed_no_credits",
            "user_message": (
                "Your available AI usage for this period is exhausted, and I do not have a safe cached answer for this question yet."
            ),
        }

    if confidence < CONFIDENCE_THRESHOLD or authority_score < AUTHORITY_THRESHOLD:
        if credits_available:
            return {
                "allowed": False,
                "decision": "needs_grounded_synthesis",
                "reason": "low_grounded_confidence",
                "user_message": (
                    "I found related material, but it is not strong enough to return directly."
                ),
            }

        return {
            "allowed": False,
            "decision": "insufficient_credits_uncached",
            "reason": "low_grounded_confidence_no_credits",
            "user_message": (
                "Your available AI usage for this period is exhausted, and I do not have a sufficiently trusted cached answer for this question yet."
            ),
        }

    answer_text = str(grounded_result.get("answer_text") or candidate.get("answer") or "").strip()
    if looks_like_ai_failure(answer_text):
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "answer_text_invalid",
            "user_message": (
                "The answer source did not produce a valid response."
            ),
        }

    return {
        "allowed": True,
        "decision": "direct_cache",
        "reason": "safe_grounded_answer",
        "answer": answer_text,
        "source": candidate.get("match_type") or "cache",
        "confidence": confidence,
        "authority_score": authority_score,
        "trust_score": trust_score,
        "grounding_mode": grounded_result.get("grounding_mode"),
        "evidence": grounded_result.get("evidence") or [],
    }
