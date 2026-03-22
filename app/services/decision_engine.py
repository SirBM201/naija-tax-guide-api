from __future__ import annotations

from typing import List

from app.schemas.ask_models import DecisionResult, QueryClassification, RetrievalCandidate


SAFE_DIRECT_INTENTS = {"definition", "obligation", "deduction", "general"}


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
    best_rank = float(best.rank_score) if best else 0.0

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

    if classification.intent_type == "calculation":
        return DecisionResult(
            mode="rules_engine",
            best_candidate=best,
            reasons=reasons + ["calculation_prefers_rules_or_grounded_basis"],
        )

    if (
        best
        and allow_direct_cache
        and classification.intent_type in SAFE_DIRECT_INTENTS
        and best_rank >= 88
    ):
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + ["high_confidence_safe_direct_cache"],
        )

    if best and best_rank >= 72 and has_ai_credit:
        return DecisionResult(
            mode="grounded_synthesis",
            best_candidate=best,
            reasons=reasons + ["good_candidate_for_grounded_synthesis"],
        )

    if best and best_rank >= 82 and allow_direct_cache and not has_ai_credit:
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + ["strong_cache_used_because_ai_credit_missing"],
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
