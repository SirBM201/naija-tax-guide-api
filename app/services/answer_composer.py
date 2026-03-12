# app/services/answer_composer.py

from __future__ import annotations

from typing import Any, Dict, List


def _normalize(value: Any) -> str:
    return str(value or "").strip()


def _build_evidence_footer(evidence: List[Dict[str, Any]]) -> str:
    if not evidence:
        return ""

    lines = []
    for item in evidence[:3]:
        title = _normalize(item.get("source_title")) or "Untitled Source"
        citation = _normalize(item.get("citation")) or "Reference not specified"
        lines.append(f"- {title}: {citation}")

    return "\n\nRelevant basis:\n" + "\n".join(lines)


def compose_final_answer(
    *,
    answer_text: str,
    question_meta: Dict[str, Any],
    refined_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Builds the final user-facing answer payload.
    """

    topic = _normalize(question_meta.get("topic"))
    intent_type = _normalize(question_meta.get("intent_type"))
    jurisdiction = _normalize(question_meta.get("jurisdiction") or "Nigeria")

    evidence = refined_result.get("evidence") or []
    confidence = refined_result.get("confidence")
    authority_score = refined_result.get("authority_score")
    grounding_mode = _normalize(refined_result.get("grounding_mode"))

    footer = _build_evidence_footer(evidence)

    final_text = _normalize(answer_text)
    if footer:
        final_text += footer

    return {
        "answer": final_text,
        "meta": {
            "topic": topic,
            "intent_type": intent_type,
            "jurisdiction": jurisdiction,
            "source": refined_result.get("source"),
            "confidence": confidence,
            "authority_score": authority_score,
            "grounding_mode": grounding_mode,
            "safe": True,
        },
    }


def compose_refusal(
    *,
    refined_result: Dict[str, Any],
    question_meta: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "answer": refined_result.get("user_message")
        or "I could not produce a sufficiently reliable answer for that question yet.",
        "meta": {
            "topic": _normalize(question_meta.get("topic")),
            "intent_type": _normalize(question_meta.get("intent_type")),
            "jurisdiction": _normalize(question_meta.get("jurisdiction") or "Nigeria"),
            "source": "none",
            "confidence": 0.0,
            "authority_score": 0.0,
            "grounding_mode": "refusal",
            "safe": True,
            "reason": refined_result.get("reason"),
            "decision": refined_result.get("decision"),
        },
    }
