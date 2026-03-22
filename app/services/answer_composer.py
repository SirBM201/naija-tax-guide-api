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
    error: Optional[str] = None


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


def _clean_lines(text: str) -> List[str]:
    raw = _safe_str(text)
    if not raw:
        return []
    lines = [ln.rstrip() for ln in raw.splitlines()]
    cleaned: List[str] = []
    blank_streak = 0
    for line in lines:
        if not line.strip():
            blank_streak += 1
            if blank_streak <= 1:
                cleaned.append("")
            continue
        blank_streak = 0
        cleaned.append(line.strip())
    while cleaned and not cleaned[0]:
        cleaned.pop(0)
    while cleaned and not cleaned[-1]:
        cleaned.pop()
    return cleaned


def _extract_source_tail(lines: List[str]) -> tuple[List[str], Optional[str]]:
    if not lines:
        return lines, None
    last = lines[-1].strip()
    if last.lower().startswith("source:"):
        return lines[:-1], last
    return lines, None


def _ensure_sentence(text: str) -> str:
    text = _safe_str(text)
    if not text:
        return ""
    if text.endswith((".", "!", "?", ":")):
        return text
    return text + "."


def _split_intro_and_steps(lines: List[str]) -> tuple[List[str], List[str]]:
    intro: List[str] = []
    steps: List[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped[:2].isdigit() or stripped.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.")):
            steps.append(stripped)
        else:
            if steps:
                steps.append(stripped)
            else:
                intro.append(stripped)
    return intro, steps


def _format_definition(text: str) -> str:
    lines = _clean_lines(text)
    lines, source_tail = _extract_source_tail(lines)
    if not lines:
        return "I could not find a reliable definition for that yet."

    first = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]

    parts = [f"Direct answer: {first}"]
    if rest:
        parts.append("Explanation:\n" + "\n".join(rest))
    if source_tail:
        parts.append(source_tail)
    return "\n\n".join(parts)


def _format_procedure(text: str) -> str:
    lines = _clean_lines(text)
    lines, source_tail = _extract_source_tail(lines)
    intro, steps = _split_intro_and_steps(lines)

    parts: List[str] = []
    if intro:
        parts.append("Direct answer:\n" + "\n".join(intro[:2]))
    if steps:
        parts.append("Steps:\n" + "\n".join(steps))
    elif lines:
        parts.append("Steps:\n1. " + "\n".join(lines))
    if source_tail:
        parts.append(source_tail)
    return "\n\n".join(parts).strip()


def _format_obligation(text: str) -> str:
    lines = _clean_lines(text)
    lines, source_tail = _extract_source_tail(lines)
    if not lines:
        return "I need a little more detail to confirm whether it applies to you."

    decision = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]
    parts = [f"Short answer: {decision}"]
    if rest:
        parts.append("Why this applies:\n" + "\n".join(rest))
    if source_tail:
        parts.append(source_tail)
    return "\n\n".join(parts)


def _format_calculation(text: str) -> str:
    lines = _clean_lines(text)
    lines, source_tail = _extract_source_tail(lines)
    if not lines:
        return "I could not confirm the exact rate, deadline, or penalty from reliable material."
    lead = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]
    parts = [f"Direct answer: {lead}"]
    if rest:
        parts.append("Basis:\n" + "\n".join(rest))
    if source_tail:
        parts.append(source_tail)
    return "\n\n".join(parts)


def _format_deduction(text: str) -> str:
    lines = _clean_lines(text)
    lines, source_tail = _extract_source_tail(lines)
    if not lines:
        return "I need a little more detail about the expense before I can answer safely."
    lead = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]
    parts = [f"Short answer: {lead}"]
    if rest:
        parts.append("Conditions and notes:\n" + "\n".join(rest))
    if source_tail:
        parts.append(source_tail)
    return "\n\n".join(parts)


def _format_general(text: str) -> str:
    lines = _clean_lines(text)
    if not lines:
        return "I could not prepare a reliable answer yet."
    return "\n".join(lines)


def render_answer(answer_text: str, *, question_meta: Optional[Dict[str, Any]] = None) -> str:
    intent_type = _safe_str((question_meta or {}).get("intent_type")).lower()

    if intent_type == "definition":
        return _format_definition(answer_text)
    if intent_type in {"procedure", "how_to"}:
        return _format_procedure(answer_text)
    if intent_type == "obligation":
        return _format_obligation(answer_text)
    if intent_type == "calculation":
        return _format_calculation(answer_text)
    if intent_type == "deduction":
        return _format_deduction(answer_text)
    return _format_general(answer_text)


def compose_direct_cache_answer(
    candidate: RetrievalCandidate,
    *,
    answer_text: Optional[str] = None,
    debug: Optional[Dict[str, Any]] = None,
    question_meta: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=render_answer(_safe_str(answer_text or candidate.answer), question_meta=question_meta),
        source="cache",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "direct_cache",
            "candidate": _candidate_meta(candidate),
            "question_meta": question_meta or {},
        },
    )


def compose_ai_answer(
    answer_text: str,
    *,
    debug: Optional[Dict[str, Any]] = None,
    question_meta: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=render_answer(_safe_str(answer_text), question_meta=question_meta),
        source="ai",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "grounded_synthesis",
            "question_meta": question_meta or {},
        },
    )


def compose_clarification(
    *,
    question_meta: Optional[Dict[str, Any]] = None,
    debug: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    topic = _safe_str((question_meta or {}).get("topic")).replace("_", " ") or "tax issue"
    return AskExecutionResult(
        ok=True,
        answer=(
            "I need a little more detail before I answer this safely.\n\n"
            f"Please clarify these points about your {topic}:\n"
            "1. Are you asking as an employee, freelancer, sole proprietor, or company?\n"
            "2. Do you want the meaning, the process, whether it applies to you, or the penalty/rate?\n"
            "3. If this is about filing or payment, which tax type is involved and for what period?"
        ),
        source="clarification",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "clarification",
            "question_meta": question_meta or {},
        },
    )


def compose_insufficient_uncached(
    *,
    debug: Optional[Dict[str, Any]] = None,
    question_meta: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=False,
        answer="",
        source="none",
        needs_credit=True,
        error="insufficient_credits_uncached",
        debug=debug or {},
        meta={
            "mode": "insufficient_credits_uncached",
            "question_meta": question_meta or {},
        },
    )


def compose_rules_engine_answer(
    answer_text: str,
    *,
    debug: Optional[Dict[str, Any]] = None,
    question_meta: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    return AskExecutionResult(
        ok=True,
        answer=render_answer(_safe_str(answer_text), question_meta=question_meta),
        source="rules_engine",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "rules_engine",
            "question_meta": question_meta or {},
        },
    )
