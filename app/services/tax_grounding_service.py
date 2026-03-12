from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


OFFICIAL_SOURCE_TYPES = {
    "firs",
    "cita",
    "vat_act",
    "pita",
    "finance_act",
    "official_notice",
    "regulation",
    "gazette",
    "court_decision",
}

NIGERIA_ALIASES = {"nigeria", "ng", "federal republic of nigeria"}


@dataclass
class GroundingEvidence:
    source_type: str
    source_title: str
    citation: str
    url: Optional[str] = None
    excerpt: Optional[str] = None
    authority_score: float = 0.0


@dataclass
class GroundedAnswer:
    grounded: bool
    grounding_mode: str
    confidence: float
    authority_score: float
    jurisdiction_ok: bool
    topic_ok: bool
    intent_ok: bool
    evidence: List[Dict[str, Any]]
    answer_text: Optional[str] = None
    refusal_reason: Optional[str] = None


def _normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _jurisdiction_ok(question_meta: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
    qj = _normalize(question_meta.get("jurisdiction") or "nigeria")
    cj = _normalize(candidate.get("jurisdiction") or "nigeria")
    return cj in NIGERIA_ALIASES and qj in NIGERIA_ALIASES


def _topic_ok(question_meta: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
    qt = _normalize(question_meta.get("topic"))
    ct = _normalize(candidate.get("topic"))
    if not qt or not ct:
        return True
    return qt == ct


def _intent_ok(question_meta: Dict[str, Any], candidate: Dict[str, Any]) -> bool:
    qi = _normalize(question_meta.get("intent_type"))
    ci = _normalize(candidate.get("intent_type"))
    if not qi or not ci:
        return True
    return qi == ci


def _collect_candidate_evidence(candidate: Dict[str, Any]) -> List[GroundingEvidence]:
    raw_items = candidate.get("sources") or candidate.get("evidence") or []
    output: List[GroundingEvidence] = []

    for item in raw_items:
        source_type = _normalize(item.get("source_type"))
        authority_score = _float(item.get("authority_score"), 0.0)

        if not authority_score:
            authority_score = 1.0 if source_type in OFFICIAL_SOURCE_TYPES else 0.45

        output.append(
            GroundingEvidence(
                source_type=source_type or "unknown",
                source_title=str(item.get("source_title") or item.get("title") or "Untitled Source"),
                citation=str(item.get("citation") or item.get("reference") or ""),
                url=item.get("url"),
                excerpt=item.get("excerpt"),
                authority_score=authority_score,
            )
        )

    return output


def _authority_score(candidate: Dict[str, Any], evidences: List[GroundingEvidence]) -> float:
    direct = _float(candidate.get("authority_score"), 0.0)
    if direct > 0:
        return min(1.0, direct)

    if not evidences:
        source_type = _normalize(candidate.get("source_type"))
        if source_type in OFFICIAL_SOURCE_TYPES:
            return 0.9
        return 0.65 if candidate.get("source") == "cache" else 0.35

    top = max(e.authority_score for e in evidences)
    avg = sum(e.authority_score for e in evidences) / len(evidences)
    return min(1.0, (top * 0.65) + (avg * 0.35))


def build_grounded_answer(
    *,
    question_meta: Dict[str, Any],
    candidate: Dict[str, Any],
    composed_answer: Optional[str] = None,
) -> GroundedAnswer:
    evidences = _collect_candidate_evidence(candidate)

    jurisdiction_ok = _jurisdiction_ok(question_meta, candidate)
    topic_ok = _topic_ok(question_meta, candidate)
    intent_ok = _intent_ok(question_meta, candidate)
    authority_score = _authority_score(candidate, evidences)
    trust_score = _float(candidate.get("trust_score"), 1.0)
    similarity = _float(
        candidate.get("similarity"),
        1.0 if candidate.get("source") == "cache" else 0.0,
    )

    confidence = min(
        1.0,
        (trust_score * 0.45)
        + (authority_score * 0.35)
        + (similarity * 0.20),
    )

    if not jurisdiction_ok:
        return GroundedAnswer(
            grounded=False,
            grounding_mode="rejected",
            confidence=confidence,
            authority_score=authority_score,
            jurisdiction_ok=False,
            topic_ok=topic_ok,
            intent_ok=intent_ok,
            evidence=[asdict(e) for e in evidences],
            refusal_reason="jurisdiction_mismatch",
        )

    if not topic_ok:
        return GroundedAnswer(
            grounded=False,
            grounding_mode="rejected",
            confidence=confidence,
            authority_score=authority_score,
            jurisdiction_ok=True,
            topic_ok=False,
            intent_ok=intent_ok,
            evidence=[asdict(e) for e in evidences],
            refusal_reason="topic_mismatch",
        )

    if not intent_ok:
        return GroundedAnswer(
            grounded=False,
            grounding_mode="rejected",
            confidence=confidence,
            authority_score=authority_score,
            jurisdiction_ok=True,
            topic_ok=True,
            intent_ok=False,
            evidence=[asdict(e) for e in evidences],
            refusal_reason="intent_mismatch",
        )

    grounding_mode = "official" if authority_score >= 0.80 else "trusted_cache"

    return GroundedAnswer(
        grounded=True,
        grounding_mode=grounding_mode,
        confidence=confidence,
        authority_score=authority_score,
        jurisdiction_ok=True,
        topic_ok=True,
        intent_ok=True,
        evidence=[asdict(e) for e in evidences],
        answer_text=composed_answer or candidate.get("answer"),
    )


def grounding_prompt_context(
    *,
    question_meta: Dict[str, Any],
    grounded: GroundedAnswer,
) -> str:
    evidence_lines: List[str] = []

    for idx, item in enumerate(grounded.evidence, start=1):
        source_type = str(item.get("source_type") or "unknown").strip()
        title = str(item.get("source_title") or "Untitled Source").strip()
        citation = str(item.get("citation") or "No citation").strip()
        excerpt = str(item.get("excerpt") or "").strip()

        line = f"{idx}. [{source_type}] {title} | {citation}"
        if excerpt:
            line += f" | {excerpt}"
        evidence_lines.append(line)

    evidence_blob = "\n".join(evidence_lines) if evidence_lines else "No evidence provided."

    return (
        "You are answering as Naija Tax Guide, a grounded Nigerian tax assistant.\n"
        "Strict rules:\n"
        "- Answer only within Nigerian tax context.\n"
        "- Do not drift into other jurisdictions.\n"
        "- Prefer approved and authoritative guidance.\n"
        "- Do not invent penalties, rates, deadlines, procedures, or legal provisions.\n"
        "- If the evidence is insufficient, say so clearly.\n"
        "- Match the user's intent. If the user asks for procedure, do not answer with only a definition.\n"
        "- If the user asks for a definition, answer with the definition first.\n"
        "\n"
        f"Question classification:\n"
        f"- topic: {question_meta.get('topic')}\n"
        f"- intent_type: {question_meta.get('intent_type')}\n"
        f"- jurisdiction: {question_meta.get('jurisdiction')}\n"
        f"- complexity: {question_meta.get('complexity')}\n"
        f"- risk_level: {question_meta.get('risk_level')}\n"
        "\n"
        f"Grounding summary:\n"
        f"- grounded: {grounded.grounded}\n"
        f"- grounding_mode: {grounded.grounding_mode}\n"
        f"- confidence: {grounded.confidence:.2f}\n"
        f"- authority_score: {grounded.authority_score:.2f}\n"
        "\n"
        f"Evidence:\n{evidence_blob}"
    )
