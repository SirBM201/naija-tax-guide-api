from __future__ import annotations

import os
from typing import Any, Dict, Optional

from app.services.query_classifier import classify_query
from app.services.semantic_cache_service import retrieve_ranked_candidates, ranked_debug_dump
from app.services.decision_engine import decide_answer_mode
from app.services.answer_composer import (
    compose_ai_answer,
    compose_clarification,
    compose_direct_cache_answer,
    compose_insufficient_uncached,
    compose_rules_engine_answer,
)
from app.services.usage_guard_service import get_ai_usage_state
from app.services.billing_guard_service import get_billing_state
from app.services.ai_service import generate_grounded_answer
from app.services.tax_grounding_service import build_grounded_answer, grounding_prompt_context
from app.services.response_refiner import refine_response
from app.services.tax_rules.vat_rules import can_handle_vat_rule, resolve_vat_rule
from app.services.tax_rules.paye_rules import can_handle_paye_rule, resolve_paye_rule


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _include_debug() -> bool:
    return _truthy(os.getenv("DEBUG_AI")) or _truthy(os.getenv("SHOW_ASK_DEBUG"))


def _candidate_to_dict(c) -> Dict[str, Any]:
    return {
        "candidate_id": c.candidate_id,
        "question": c.question,
        "answer": c.answer,
        "canonical_key": c.canonical_key,
        "intent_type": c.intent_type,
        "topic": c.topic,
        "jurisdiction": c.jurisdiction,
        "lang": c.lang,
        "trust_score": c.trust_score,
        "review_status": c.review_status,
        "source_authority_score": c.source_authority_score,
        "authority_score": c.source_authority_score,
        "similarity": c.similarity,
        "match_type": c.match_type,
        "rank_score": c.rank_score,
        "source": "cache",
    }


def _classification_to_meta(classification) -> Dict[str, Any]:
    return {
        "topic": classification.topic,
        "intent_type": classification.intent_type,
        "jurisdiction": classification.jurisdiction or "nigeria",
        "complexity": classification.complexity,
        "risk_level": classification.risk_level,
        "normalized_question": classification.normalized_question,
        "canonical_key": classification.canonical_key,
    }


def _resolve_rules(question: str, topic: str, intent_type: str) -> Optional[str]:
    if can_handle_vat_rule(question, topic, intent_type):
        return resolve_vat_rule(question, intent_type)

    if can_handle_paye_rule(question, topic, intent_type):
        return resolve_paye_rule(question, intent_type)

    return None


def _filtered_debug(debug: Dict[str, Any]) -> Dict[str, Any]:
    if _include_debug():
        return debug
    return {}


def _try_safe_candidate_answer(
    *,
    candidate,
    question_meta: Dict[str, Any],
    credits_available: bool,
) -> Optional[Dict[str, Any]]:
    if not candidate:
        return None

    candidate_dict = _candidate_to_dict(candidate)

    grounded = build_grounded_answer(
        question_meta=question_meta,
        candidate=candidate_dict,
        composed_answer=candidate_dict.get("answer"),
    )

    refined = refine_response(
        question_meta=question_meta,
        candidate=candidate_dict,
        grounded_result=grounded.__dict__,
        credits_available=credits_available,
    )

    if refined.get("allowed"):
        return {
            "allowed": True,
            "answer": str(refined.get("answer") or candidate.answer or "").strip(),
            "grounded": grounded.__dict__,
            "refined": refined,
        }

    return {
        "allowed": False,
        "grounded": grounded.__dict__,
        "refined": refined,
    }


def ask_guarded(
    *,
    account_id: str,
    question: str,
    lang: str = "en",
    channel: str = "web",
) -> Dict[str, Any]:
    classification = classify_query(question, lang=lang)
    question_meta = _classification_to_meta(classification)

    usage_state = get_ai_usage_state(account_id)
    billing_state = get_billing_state(account_id)
    credits_available = bool(usage_state.get("has_ai_credit"))

    ranked = retrieve_ranked_candidates(classification)

    decision = decide_answer_mode(
        classification,
        ranked,
        has_ai_credit=credits_available,
        monthly_ai_usage=int(usage_state["monthly_ai_usage"]),
        monthly_ai_limit=int(usage_state["monthly_ai_limit"]),
    )

    debug = {
        "classification": classification.__dict__,
        "billing_state": billing_state,
        "usage_state": usage_state,
        "decision": {
            "mode": decision.mode,
            "reasons": decision.reasons,
        },
        "ranked_candidates": ranked_debug_dump(ranked[:5]),
    }

    if decision.mode == "clarification":
        res = compose_clarification(debug=_filtered_debug(debug))
        return res.__dict__

    if decision.mode == "rules_engine":
        rule_answer = _resolve_rules(question, classification.topic, classification.intent_type)
        if rule_answer:
            res = compose_rules_engine_answer(rule_answer, debug=_filtered_debug(debug))
            return res.__dict__

    best_candidate = decision.best_candidate or (ranked[0] if ranked else None)

    # IMPORTANT:
    # Always try a safe candidate answer first before falling into grounded synthesis.
    # This prevents simple definition questions from returning internal-style synthesis text.
    safe_candidate = _try_safe_candidate_answer(
        candidate=best_candidate,
        question_meta=question_meta,
        credits_available=credits_available,
    )

    if safe_candidate:
        debug["candidate_grounding"] = safe_candidate.get("grounded")
        debug["candidate_refiner"] = safe_candidate.get("refined")

        if safe_candidate.get("allowed"):
            res = compose_direct_cache_answer(
                best_candidate,
                answer_text=safe_candidate.get("answer"),
                debug=_filtered_debug(debug),
            )
            return res.__dict__

    if decision.mode == "insufficient_credits_uncached" or not credits_available:
        res = compose_insufficient_uncached(debug=_filtered_debug(debug))
        return res.__dict__

    if decision.mode == "grounded_synthesis" or decision.mode == "direct_cache":
        grounded_candidates = [_candidate_to_dict(c) for c in ranked[:3]]

        grounding_context = None
        if grounded_candidates:
            grounded_preview = build_grounded_answer(
                question_meta=question_meta,
                candidate=grounded_candidates[0],
                composed_answer=grounded_candidates[0].get("answer"),
            )
            grounding_context = grounding_prompt_context(
                question_meta=question_meta,
                grounded=grounded_preview,
            )
            debug["grounded_preview"] = grounded_preview.__dict__

        answer_text = generate_grounded_answer(
            question=question,
            lang=lang,
            candidates=grounded_candidates,
            grounding_context=grounding_context,
        )

        res = compose_ai_answer(answer_text, debug=_filtered_debug(debug))
        return res.__dict__

    res = compose_insufficient_uncached(debug=_filtered_debug(debug))
    return res.__dict__
