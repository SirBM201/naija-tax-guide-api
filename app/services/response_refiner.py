from __future__ import annotations

from typing import Any, Dict, Optional


TRUST_THRESHOLD = 0.60
CONFIDENCE_THRESHOLD = 0.58
AUTHORITY_THRESHOLD = 0.50


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
        "openai_call_failed",
        "openai_empty_answer",
        "openai_sdk_missing",
        "incorrect api key provided",
        "invalid_request_error",
        "sk-proj-",
        "status: 401",
        "error code: 401",
    ]
    return any(p in t for p in bad_patterns)


def _extract_answer_text(
    grounded_result: Optional[Dict[str, Any]],
    candidate: Optional[Dict[str, Any]],
) -> str:
    if grounded_result:
        for key in ("answer_text", "answer", "final_answer", "response"):
            value = str(grounded_result.get(key) or "").strip()
            if value:
                return value

    if candidate:
        for key in ("answer", "text_content", "summary"):
            value = str(candidate.get(key) or "").strip()
            if value:
                return value

    return ""


def _is_nigeria(value: Any) -> bool:
    v = _normalize(value)
    return v in {"nigeria", "ng"}


def refine_response(
    *,
    question_meta: Dict[str, Any],
    candidate: Optional[Dict[str, Any]],
    grounded_result: Optional[Dict[str, Any]],
    credits_available: bool,
) -> Dict[str, Any]:
    """
    Final validation layer before the answer leaves the backend.

    Updated policy:
    - Prefer a valid grounded result if present
    - Do not fail merely because candidate is absent
    - Do not over-block on rigid topic/intent equality
    - Only reject on real safety / validity failures
    """

    question_topic = question_meta.get("topic")
    question_intent = question_meta.get("intent_type")
    question_jurisdiction = question_meta.get("jurisdiction") or "nigeria"

    candidate_topic = candidate.get("topic") if candidate else None
    candidate_intent = candidate.get("intent_type") if candidate else None
    candidate_jurisdiction = (candidate.get("jurisdiction") if candidate else None) or "nigeria"
    review_status = _normalize(candidate.get("review_status") if candidate else "approved") or "approved"
    trust_score = _float(candidate.get("trust_score") if candidate else 1.0, 1.0)

    grounded = bool((grounded_result or {}).get("grounded"))
    confidence = _float((grounded_result or {}).get("confidence"), 0.0)
    authority_score = _float((grounded_result or {}).get("authority_score"), 0.0)
    grounding_mode = (grounded_result or {}).get("grounding_mode")
    evidence = (grounded_result or {}).get("evidence") or []

    jurisdiction_ok = bool((grounded_result or {}).get("jurisdiction_ok", True))
    topic_ok = bool((grounded_result or {}).get("topic_ok", True))
    intent_ok = bool((grounded_result or {}).get("intent_ok", True))

    answer_text = _extract_answer_text(grounded_result, candidate)

    if looks_like_ai_failure(answer_text):
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "answer_text_invalid",
            "user_message": "The answer source did not produce a valid response.",
        }

    if not answer_text:
        if credits_available:
            return {
                "allowed": False,
                "decision": "needs_grounding",
                "reason": "empty_answer_text",
                "user_message": "I could not generate a usable answer for that question yet.",
            }
        return {
            "allowed": False,
            "decision": "insufficient_credits_uncached",
            "reason": "empty_answer_text_no_credits",
            "user_message": (
                "Your available AI usage for this period is exhausted, and I do not yet have a usable cached answer for this question."
            ),
        }

    # Hard stop only for wrong jurisdiction
    if not _is_nigeria(question_jurisdiction):
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "unsupported_question_jurisdiction",
            "user_message": "This assistant only answers within Nigerian tax context.",
        }

    if candidate and not _is_nigeria(candidate_jurisdiction):
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "jurisdiction_mismatch",
            "user_message": "I found related material, but it is not aligned with Nigerian tax context.",
        }

    if grounded_result:
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

        if not jurisdiction_ok:
            return {
                "allowed": False,
                "decision": "reject",
                "reason": "grounded_jurisdiction_failed",
                "user_message": "I found related material, but it is not aligned with Nigerian tax context.",
            }

        # Topic/intent mismatch should not hard-fail if confidence is still good.
        weak_match = (not topic_ok or not intent_ok) and confidence < 0.70
        if weak_match:
            if credits_available:
                return {
                    "allowed": False,
                    "decision": "needs_grounded_synthesis",
                    "reason": "weak_topic_or_intent_match",
                    "user_message": (
                        "I found related material, but I need a better-grounded synthesis before answering confidently."
                    ),
                }
            return {
                "allowed": False,
                "decision": "insufficient_credits_uncached",
                "reason": "weak_topic_or_intent_match_no_credits",
                "user_message": (
                    "Your available AI usage for this period is exhausted, and I do not yet have a safe cached answer for this exact question."
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

        return {
            "allowed": True,
            "decision": "grounded_answer",
            "reason": "safe_grounded_answer",
            "answer": answer_text,
            "source": (candidate or {}).get("match_type") or "grounded",
            "confidence": confidence,
            "authority_score": authority_score,
            "trust_score": trust_score,
            "grounding_mode": grounding_mode,
            "evidence": evidence,
        }

    # No grounded_result: allow strong approved cache answer
    if not candidate:
        if credits_available:
            return {
                "allowed": False,
                "decision": "needs_grounding",
                "reason": "no_candidate_no_grounding",
                "user_message": "I could not find a sufficiently reliable answer for that question yet.",
            }
        return {
            "allowed": False,
            "decision": "insufficient_credits_uncached",
            "reason": "no_candidate_no_grounding_no_credits",
            "user_message": (
                "Your available AI usage for this period is exhausted, and I do not yet have a safe cached answer for this question."
            ),
        }

    if review_status != "approved":
        return {
            "allowed": False,
            "decision": "reject",
            "reason": "unapproved_answer",
            "user_message": "That answer is not yet approved for reliable use.",
        }

    if trust_score < TRUST_THRESHOLD:
        if credits_available:
            return {
                "allowed": False,
                "decision": "needs_grounding",
                "reason": "low_trust_cache_requires_grounding",
                "user_message": (
                    "I found related material, but it is not trusted enough to return directly."
                ),
            }
        return {
            "allowed": False,
            "decision": "insufficient_credits_uncached",
            "reason": "low_trust_cache_no_credits",
            "user_message": (
                "Your available AI usage for this period is exhausted, and I do not yet have a sufficiently trusted cached answer for this question."
            ),
        }

    return {
        "allowed": True,
        "decision": "direct_cache",
        "reason": "safe_cache_answer",
        "answer": answer_text,
        "source": candidate.get("match_type") or "cache",
        "confidence": max(confidence, 0.60),
        "authority_score": max(authority_score, 0.50),
        "trust_score": trust_score,
        "grounding_mode": grounding_mode,
        "evidence": evidence,
    }
