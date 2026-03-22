from __future__ import annotations

from typing import List

from app.schemas.ask_models import DecisionResult, QueryClassification, RetrievalCandidate


SAFE_DIRECT_INTENTS = {
    "definition",
    "obligation",
    "eligibility",
    "deduction",
    "general",
    "rate",
    "exemption",
}

SYNTHESIS_PREFERRED_INTENTS = {
    "procedure",
    "how_to",
    "calculation",
    "computation",
    "guidance",
}

TAX_RELATED_INTENTS = SAFE_DIRECT_INTENTS | SYNTHESIS_PREFERRED_INTENTS | {
    "compliance",
    "filing",
    "payment",
}


def _best_rank(candidate: RetrievalCandidate | None) -> float:
    if not candidate:
        return 0.0
    try:
        return float(candidate.rank_score or 0.0)
    except Exception:
        return 0.0


def _candidate_topic(candidate: RetrievalCandidate | None) -> str:
    if not candidate:
        return ""
    try:
        return str(getattr(candidate, "topic", "") or "").strip().lower()
    except Exception:
        return ""


def _classification_topic(classification: QueryClassification) -> str:
    try:
        return str(classification.topic or "").strip().lower()
    except Exception:
        return ""


def _intent(classification: QueryClassification) -> str:
    try:
        return str(classification.intent_type or "").strip().lower()
    except Exception:
        return "general"


def _complexity(classification: QueryClassification) -> str:
    try:
        return str(classification.complexity or "").strip().lower()
    except Exception:
        return "basic"


def _risk_level(classification: QueryClassification) -> str:
    try:
        return str(classification.risk_level or "").strip().lower()
    except Exception:
        return "low"


def _topic_matches(classification: QueryClassification, candidate: RetrievalCandidate | None) -> bool:
    c_topic = _classification_topic(classification)
    r_topic = _candidate_topic(candidate)

    if not c_topic or not r_topic:
        return False

    if c_topic == r_topic:
        return True

    keyword_overlap = {
        ("vat", "value_added_tax"),
        ("value_added_tax", "vat"),
        ("paye", "personal_income_tax"),
        ("personal_income_tax", "paye"),
        ("freelancer", "personal_income_tax"),
        ("self_employed", "personal_income_tax"),
    }

    return (c_topic, r_topic) in keyword_overlap


def decide_answer_mode(
    classification: QueryClassification,
    ranked_candidates: List[RetrievalCandidate],
    *,
    has_ai_credit: bool,
    monthly_ai_usage: int,
    monthly_ai_limit: int,
    allow_direct_cache: bool = True,
) -> DecisionResult:
    best = ranked_candidates[0] if ranked_candidates else None
    best_rank = _best_rank(best)
    intent = _intent(classification)
    complexity = _complexity(classification)
    risk = _risk_level(classification)
    topic_match = _topic_matches(classification, best)
    has_candidate = best is not None

    reasons = [
        f"intent={intent}",
        f"topic={_classification_topic(classification)}",
        f"complexity={complexity}",
        f"risk_level={risk}",
        f"has_ai_credit={has_ai_credit}",
        f"monthly_ai_usage={monthly_ai_usage}",
        f"monthly_ai_limit={monthly_ai_limit}",
        f"allow_direct_cache={allow_direct_cache}",
        f"has_candidate={has_candidate}",
        f"best_rank={best_rank}",
        f"topic_match={topic_match}",
    ]

    if classification.requires_clarification:
        return DecisionResult(
            mode="clarification",
            best_candidate=best,
            reasons=reasons + ["requires_clarification=true"],
        )

    if not has_candidate:
        if has_ai_credit:
            return DecisionResult(
                mode="grounded_synthesis",
                best_candidate=None,
                reasons=reasons + ["no_ranked_candidate_fallback_to_ai"],
            )
        return DecisionResult(
            mode="insufficient_credits_uncached",
            best_candidate=None,
            reasons=reasons + ["no_ranked_candidate_and_no_ai_credit"],
        )

    # Very strong direct answer from cache
    if allow_direct_cache and intent in SAFE_DIRECT_INTENTS and best_rank >= 82 and topic_match:
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + ["strong_safe_cache_match"],
        )

    # For definitions/rates/exemptions, a decent exact-topic match can answer directly
    if allow_direct_cache and intent in {"definition", "rate", "exemption"} and best_rank >= 70 and topic_match:
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + ["definition_or_rate_uses_cache"],
        )

    # Procedures, compliance, filing, calculation should prefer synthesis whenever we have something relevant
    if intent in SYNTHESIS_PREFERRED_INTENTS or intent in {"compliance", "filing", "payment"}:
        if has_ai_credit and (best_rank >= 40 or topic_match):
            return DecisionResult(
                mode="grounded_synthesis",
                best_candidate=best,
                reasons=reasons + ["procedure_or_guidance_prefers_synthesis"],
            )

    # If we have a relevant topic match, do not reject too early
    if has_ai_credit and topic_match and best_rank >= 35:
        return DecisionResult(
            mode="grounded_synthesis",
            best_candidate=best,
            reasons=reasons + ["relevant_topic_candidate_used_for_synthesis"],
        )

    # If question is low-risk/basic tax guidance, allow synthesis with weaker matches
    if has_ai_credit and intent in TAX_RELATED_INTENTS and complexity in {"basic", "moderate"} and risk in {"low", "medium"} and best_rank >= 30:
        return DecisionResult(
            mode="grounded_synthesis",
            best_candidate=best,
            reasons=reasons + ["basic_tax_question_uses_synthesis"],
        )

    # If AI is not available but cache is still decent, use cache instead of dead-ending
    if allow_direct_cache and best_rank >= 68:
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + ["fallback_to_cache_without_strong_ai_path"],
        )

    if not has_ai_credit:
        return DecisionResult(
            mode="insufficient_credits_uncached",
            best_candidate=best,
            reasons=reasons + ["no_ai_credit_and_match_too_weak_for_safe_cache"],
        )

    # Final fallback: if there is any candidate at all and AI credit exists, synthesize
    return DecisionResult(
        mode="grounded_synthesis",
        best_candidate=best,
        reasons=reasons + ["final_grounded_synthesis_fallback"],
    )
