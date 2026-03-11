# app/services/answer_composer.py
from __future__ import annotations

from typing import Dict, Any


def compose_direct_cache_answer(candidate: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ok": True,
        "answer": candidate.get("answer") or "",
        "mode": "direct_cache",
        "confidence": candidate.get("_rank_score", 0),
        "meta": {
            "match_type": candidate.get("match_type"),
            "topic": candidate.get("topic"),
            "intent_type": candidate.get("intent_type"),
            "source_type": candidate.get("source_type"),
        },
    }


def compose_insufficient_uncached() -> Dict[str, Any]:
    return {
        "ok": False,
        "error": "insufficient_credits",
        "answer": (
            "This question does not match a trusted cached answer, and your AI credits are currently exhausted. "
            "Please top up or move to a plan that includes more AI usage."
        ),
        "mode": "insufficient_credits_uncached",
    }
