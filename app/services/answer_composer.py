from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.schemas.ask_models import RetrievalCandidate


@dataclass
class AskExecutionResult:
    ok: bool
    answer: str
    source: str
    needs_credit: bool = False
    debug: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _candidate_meta(candidate: RetrievalCandidate) -> Dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "canonical_key": candidate.canonical_key,
        "topic": candidate.topic,
        "intent_type": candidate.intent_type,
        "jurisdiction": candidate.jurisdiction,
        "lang": candidate.lang,
        "trust_score": candidate.trust_score,
        "source_authority_score": candidate.source_authority_score,
        "similarity": candidate.similarity,
        "match_type": candidate.match_type,
        "rank_score": candidate.rank_score,
        "review_status": candidate.review_status,
    }


def compose_direct_cache_answer(
    candidate: RetrievalCandidate,
    *,
    debug: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=_safe_str(candidate.answer),
        source="cache",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "direct_cache",
            "candidate": _candidate_meta(candidate),
        },
    )


def compose_ai_answer(
    answer_text: str,
    *,
    debug: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=_safe_str(answer_text),
        source="ai",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "grounded_synthesis",
        },
    )


def compose_clarification(
    *,
    debug: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=(
            "I need a little more detail to answer that safely. "
            "Please clarify the tax type, taxpayer type, or exact action you want to take."
        ),
        source="clarification",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "clarification",
        },
    )


def compose_insufficient_uncached(
    *,
    debug: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=False,
        answer=(
            "Your available AI usage for this period is exhausted, and I do not have a sufficiently reliable cached answer for this question yet."
        ),
        source="none",
        needs_credit=True,
        debug=debug or {},
        meta={
            "mode": "insufficient_credits_uncached",
        },
    )


def compose_rules_engine_answer(
    answer_text: str,
    *,
    debug: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=_safe_str(answer_text),
        source="rules_engine",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "rules_engine",
        },
    )
