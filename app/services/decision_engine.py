from __future__ import annotations

from typing import List

from app.schemas.ask_models import DecisionResult, QueryClassification, RetrievalCandidate


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

    reasons = [
        f"intent={classification.intent_type}",
        f"topic={classification.topic}",
        f"complexity={classification.complexity}",
        f"has_ai_credit={has_ai_credit}",
        f"monthly_ai_usage={monthly_ai_usage}",
        f"monthly_ai_limit={monthly_ai_limit}",
        f"allow_direct_cache={allow_direct_cache}",
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
            reasons=reasons + ["intent=calculation"],
        )

    if best and best.rank_score >= 85 and allow_direct_cache:
        return DecisionResult(
            mode="direct_cache",
            best_candidate=best,
            reasons=reasons + [f"best_rank={best.rank_score}", "candidate_strong_enough_for_cache_review"],
        )

    if best and best.rank_score >= 70 and has_ai_credit:
        return DecisionResult(
            mode="grounded_synthesis",
            best_candidate=best,
            reasons=reasons + [f"best_rank={best.rank_score}", "candidate_good_for_grounded_synthesis"],
        )

    if not has_ai_credit:
        return DecisionResult(
            mode="insufficient_credits_uncached",
            best_candidate=best,
            reasons=reasons + ["no_ai_credit_and_no_safe_direct_cache"],
        )

    return DecisionResult(
        mode="grounded_synthesis",
        best_candidate=best,
        reasons=reasons + ["fallback_grounded_synthesis"],
    )
