from __future__ import annotations

from app.schemas.ask_models import AskExecutionResult, RetrievalCandidate


def compose_direct_cache_answer(candidate: RetrievalCandidate, debug: dict | None = None) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=candidate.answer or "",
        mode="direct_cache",
        confidence=candidate.rank_score,
        debug=debug or {},
    )


def compose_clarification(debug: dict | None = None) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=(
            "I can help with that, but I need one clarification first so I do not give you the wrong tax guidance. "
            "Please tell me the exact business type, tax type, or filing context involved."
        ),
        mode="clarification",
        confidence=0.60,
        debug=debug or {},
    )


def compose_insufficient_uncached(debug: dict | None = None) -> AskExecutionResult:
    return AskExecutionResult(
        ok=False,
        error="insufficient_credits",
        fix="Please top up or move to a plan with more AI usage for fresh uncached questions.",
        answer=(
            "This question does not match a trusted cached answer, and your AI credits are currently exhausted. "
            "Please top up or upgrade your plan to unlock a fresh AI-generated answer."
        ),
        mode="insufficient_credits_uncached",
        confidence=0.0,
        debug=debug or {},
    )


def compose_rules_engine_answer(answer_text: str, debug: dict | None = None) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=answer_text,
        mode="rules_engine",
        confidence=0.95,
        debug=debug or {},
    )


def compose_ai_answer(answer_text: str, debug: dict | None = None) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=answer_text,
        mode="grounded_synthesis",
        confidence=0.80,
        debug=debug or {},
    )
