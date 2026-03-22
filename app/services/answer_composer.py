from __future__ import annotations

import re
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


_INTERNAL_PATTERNS = [
    r"(?im)^grounded basis:.*?$",
    r"(?im)^grounding context:.*?$",
    r"(?im)^grounding summary:.*?$",
    r"(?im)^strict rules:.*?$",
    r"(?im)^question classification:.*?$",
    r"(?im)^candidate\s+\d+:.*?$",
    r"(?im)^evidence:.*?$",
    r"(?im)^debug:.*?$",
    r"(?im)^system prompt:.*?$",
    r"(?im)^prompt:.*?$",
    r"(?im)^match_type:.*?$",
    r"(?im)^similarity:.*?$",
    r"(?im)^trust_score:.*?$",
    r"(?im)^authority_score:.*?$",
    r"(?im)^source_authority_score:.*?$",
    r"(?im)^rank_score:.*?$",
    r"(?im)^review_status:.*?$",
    r"(?im)^topic:.*?$",
    r"(?im)^intent_type:.*?$",
    r"(?im)^jurisdiction:.*?$",
    r"(?im)^complexity:.*?$",
    r"(?im)^risk_level:.*?$",
    r"(?im)^source id:.*?$",
    r"(?im)^source title:.*?$",
    r"(?im)^chunk id:.*?$",
]

_PROVIDER_ERROR_PATTERNS = [
    r"incorrect api key provided",
    r"invalid_api_key",
    r"openai",
    r"sk-proj-",
    r"status:\s*401",
    r"error code:\s*401",
    r"invalid_request_error",
    r"api key",
]

_GENERIC_BAD_RESPONSE_PATTERNS = [
    r"ai temporarily unavailable",
    r"no evidence provided",
    r"you are answering as",
    r"based on the strongest available",
    r"best supported answer",
]


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _candidate_meta(candidate: Any) -> Dict[str, Any]:
    if isinstance(candidate, dict):
        return {
            "candidate_id": candidate.get("candidate_id"),
            "canonical_key": candidate.get("canonical_key"),
            "topic": candidate.get("topic"),
            "intent_type": candidate.get("intent_type"),
            "jurisdiction": candidate.get("jurisdiction"),
            "lang": candidate.get("lang"),
            "trust_score": candidate.get("trust_score"),
            "source_authority_score": candidate.get("source_authority_score"),
            "similarity": candidate.get("similarity"),
            "match_type": candidate.get("match_type"),
            "rank_score": candidate.get("rank_score"),
            "review_status": candidate.get("review_status"),
            "source_title": candidate.get("source_title"),
        }

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


def _ensure_sentence(text: str) -> str:
    text = _safe_str(text)
    if not text:
        return ""
    if text.endswith((".", "!", "?", ":")):
        return text
    return text + "."


def _extract_source_tail(lines: List[str]) -> tuple[List[str], Optional[str]]:
    if not lines:
        return lines, None

    last = lines[-1].strip()
    if last.lower().startswith("source:"):
        return lines[:-1], last

    return lines, None


def _sanitize_answer_text(text: str) -> str:
    cleaned = _safe_str(text)
    if not cleaned:
        return ""

    for pattern in _INTERNAL_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned)

    lines = _clean_lines(cleaned)
    filtered: List[str] = []

    for line in lines:
        lower = line.strip().lower()

        if any(marker in lower for marker in _PROVIDER_ERROR_PATTERNS):
            continue

        if any(marker in lower for marker in _GENERIC_BAD_RESPONSE_PATTERNS):
            continue

        if lower.startswith("- ") and any(
            bad in lower
            for bad in [
                "topic:",
                "intent_type:",
                "jurisdiction:",
                "trust_score:",
                "similarity:",
                "match_type:",
                "authority_score:",
                "review_status:",
                "grounded:",
                "grounding_mode:",
                "confidence:",
            ]
        ):
            continue

        filtered.append(line)

    return "\n".join(_clean_lines("\n".join(filtered))).strip()


def looks_like_internal_or_broken_answer(text: str) -> bool:
    raw = _safe_str(text).lower()
    if not raw:
        return True

    bad_signals = [
        "candidate 1",
        "candidate 2",
        "candidate 3",
        "grounded basis",
        "grounding context",
        "grounding summary",
        "strict rules",
        "question classification",
        "trust_score",
        "similarity",
        "match_type",
        "invalid_api_key",
        "incorrect api key provided",
        "sk-proj-",
        "you are answering as",
        "no evidence provided",
    ]

    return any(signal in raw for signal in bad_signals)


def _split_intro_and_steps(lines: List[str]) -> tuple[List[str], List[str]]:
    intro: List[str] = []
    steps: List[str] = []

    for line in lines:
        stripped = line.strip()
        if re.match(r"^\d+[.)]\s+", stripped):
            steps.append(stripped)
        elif steps and stripped:
            steps.append(stripped)
        else:
            intro.append(stripped)

    return intro, steps


def _format_definition(text: str) -> str:
    lines = _clean_lines(_sanitize_answer_text(text))
    lines, source_tail = _extract_source_tail(lines)

    if not lines:
        return "I do not yet have enough reliable guidance in the system to define that properly."

    first = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]

    parts = [first]
    if rest:
        parts.append("\n".join(rest))
    if source_tail:
        parts.append(source_tail)

    return "\n\n".join(parts).strip()


def _format_procedure(text: str) -> str:
    lines = _clean_lines(_sanitize_answer_text(text))
    lines, source_tail = _extract_source_tail(lines)

    if not lines:
        return "I do not yet have enough reliable guidance in the system to give the correct procedure."

    intro, steps = _split_intro_and_steps(lines)
    parts: List[str] = []

    if intro:
        parts.append("\n".join(intro[:2]))

    if steps:
        parts.append("Steps:\n" + "\n".join(steps))
    elif len(lines) > 1:
        numbered = [f"{i+1}. {line}" for i, line in enumerate(lines[1:])]
        parts = [_ensure_sentence(lines[0]), "Steps:\n" + "\n".join(numbered)]
    else:
        parts = [_ensure_sentence(lines[0])]

    if source_tail:
        parts.append(source_tail)

    return "\n\n".join(parts).strip()


def _format_obligation(text: str) -> str:
    lines = _clean_lines(_sanitize_answer_text(text))
    lines, source_tail = _extract_source_tail(lines)

    if not lines:
        return "I need a little more detail before I can confirm whether this applies."

    decision = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]

    parts = [decision]
    if rest:
        parts.append("\n".join(rest))
    if source_tail:
        parts.append(source_tail)

    return "\n\n".join(parts).strip()


def _format_calculation(text: str) -> str:
    lines = _clean_lines(_sanitize_answer_text(text))
    lines, source_tail = _extract_source_tail(lines)

    if not lines:
        return "I do not yet have enough reliable guidance in the system to confirm the exact rate, deadline, or penalty."

    lead = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]

    parts = [lead]
    if rest:
        parts.append("\n".join(rest))
    if source_tail:
        parts.append(source_tail)

    return "\n\n".join(parts).strip()


def _format_deduction(text: str) -> str:
    lines = _clean_lines(_sanitize_answer_text(text))
    lines, source_tail = _extract_source_tail(lines)

    if not lines:
        return "I need a little more detail about that expense before I can answer safely."

    lead = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]

    parts = [lead]
    if rest:
        parts.append("\n".join(rest))
    if source_tail:
        parts.append(source_tail)

    return "\n\n".join(parts).strip()


def _format_general(text: str) -> str:
    cleaned = _sanitize_answer_text(text)
    lines = _clean_lines(cleaned)

    if not lines:
        return "I do not yet have enough reliable guidance in the system to answer that accurately."

    lines, source_tail = _extract_source_tail(lines)
    first = _ensure_sentence(lines[0])
    rest = [ln for ln in lines[1:] if ln]

    parts = [first]
    if rest:
        parts.append("\n".join(rest))
    if source_tail:
        parts.append(source_tail)

    return "\n\n".join(parts).strip()


def render_answer(answer_text: str, *, question_meta: Optional[Dict[str, Any]] = None) -> str:
    intent_type = _safe_str((question_meta or {}).get("intent_type")).lower()
    topic = _safe_str((question_meta or {}).get("topic")).lower()
    sanitized = _sanitize_answer_text(answer_text)

    if looks_like_internal_or_broken_answer(sanitized):
        return "I do not yet have enough reliable guidance in the system to answer that accurately."

    if intent_type == "definition":
        return _format_definition(sanitized)

    if intent_type in {"procedure", "how_to"}:
        return _format_procedure(sanitized)

    if intent_type in {"obligation", "eligibility"}:
        return _format_obligation(sanitized)

    if intent_type == "calculation":
        return _format_calculation(sanitized)

    if intent_type == "deduction":
        return _format_deduction(sanitized)

    if topic in {"penalty", "rate", "deadline"}:
        return _format_calculation(sanitized)

    return _format_general(sanitized)


def compose_direct_cache_answer(
    candidate: Any,
    *,
    answer_text: Optional[str] = None,
    debug: Optional[Dict[str, Any]] = None,
    question_meta: Optional[Dict[str, Any]] = None,
) -> AskExecutionResult:
    raw_answer = _safe_str(answer_text or (candidate.get("answer") if isinstance(candidate, dict) else candidate.answer))
    rendered = render_answer(raw_answer, question_meta=question_meta)

    return AskExecutionResult(
        ok=True,
        answer=rendered,
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
    rendered = render_answer(_safe_str(answer_text), question_meta=question_meta)

    return AskExecutionResult(
        ok=True,
        answer=rendered,
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
    rendered = render_answer(_safe_str(answer_text), question_meta=question_meta)

    return AskExecutionResult(
        ok=True,
        answer=rendered,
        source="rules_engine",
        needs_credit=False,
        debug=debug or {},
        meta={
            "mode": "rules_engine",
            "question_meta": question_meta or {},
        },
    )
