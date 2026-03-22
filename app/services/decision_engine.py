from __future__ import annotations

from typing import List

from app.schemas.ask_models import DecisionResult, QueryClassification, RetrievalCandidate


SAFE_DIRECT_INTENTS = {
    "definition",
    "obligation",
    "eligibility",
    "deduction",
    "general",
}

SYNTHESIS_PREFERRED_INTENTS = {
    "procedure",
    "how_to",
    "calculation",
}


def _best_rank(candidate: RetrievalCandidate | None) -> float:
    if not candidate:
        return 0.0
    try:
        return float(candidate.rank_score)
    except Exception:
        return 0.0


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

    reasons = [
        f"intent={classification.intent_type}",
        f"topic={classification.topic}",
        f"complexity={classification.complexity}",
        f"has_ai_credit={has_ai_credit}",
        f"monthly_ai_usage={monthly_ai_usage}",
        f"monthly_ai_limit={monthly_ai_limit}",
        f"allow_direct_cache={allow_direct_cache}",
        f"best_rank={best_rank}",
    ]

    if classification.requires_clarification:
        return DecisionResult(
            mode="clarification",
            best_candidate=best,
            reasons=reasons + ["requires_clarification=true"],
        )

    if best and allow_direct_cache and classification.intent_type in SAFE_DIRECT_INTENTS and best_rank >= 90:
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + ["very_strong_safe_cache_match"],
        )

    if best and classification.intent_type in SYNTHESIS_PREFERRED_INTENTS and has_ai_credit and best_rank >= 55:
        return DecisionResult(
            mode="grounded_synthesis",
            best_candidate=best,
            reasons=reasons + ["intent_prefers_grounded_synthesis"],
        )

    if best and has_ai_credit and best_rank >= 68:
        return DecisionResult(
            mode="grounded_synthesis",
            best_candidate=best,
            reasons=reasons + ["good_candidate_for_grounded_synthesis"],
        )

    if best and allow_direct_cache and best_rank >= 84 and not has_ai_credit:
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + ["strong_cache_used_because_ai_credit_missing"],
        )

    if best and allow_direct_cache and best_rank >= 86:
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + ["fallback_to_strong_cache"],
        )

    if not has_ai_credit:
        return DecisionResult(
            mode="insufficient_credits_uncached",
            best_candidate=best,
            reasons=reasons + ["no_ai_credit_and_no_safe_match"],
        )

    return DecisionResult(
        mode="grounded_synthesis",
        best_candidate=best,
        reasons=reasons + ["fallback_grounded_synthesis"],
    )
