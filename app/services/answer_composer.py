from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AskExecutionResult:
    ok: bool
    answer: str
    source: str
    needs_credit: bool = False
    debug: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


_INTERNAL_HEADER_PATTERNS = [
    r"(?im)^grounded basis:\s*$",
    r"(?im)^grounding context:\s*$",
    r"(?im)^grounding summary:\s*$",
    r"(?im)^strict rules:\s*$",
    r"(?im)^question classification:\s*$",
    r"(?im)^evidence:\s*$",
    r"(?im)^debug:\s*$",
    r"(?im)^system prompt:\s*$",
    r"(?im)^prompt:\s*$",
]

_INTERNAL_FIELD_LINE_PATTERNS = [
    r"(?im)^-?\s*topic:\s*.*$",
    r"(?im)^-?\s*intent_type:\s*.*$",
    r"(?im)^-?\s*jurisdiction:\s*.*$",
    r"(?im)^-?\s*complexity:\s*.*$",
    r"(?im)^-?\s*risk_level:\s*.*$",
    r"(?im)^-?\s*trust_score:\s*.*$",
    r"(?im)^-?\s*similarity:\s*.*$",
    r"(?im)^-?\s*match_type:\s*.*$",
    r"(?im)^-?\s*authority_score:\s*.*$",
    r"(?im)^-?\s*source_authority_score:\s*.*$",
    r"(?im)^-?\s*rank_score:\s*.*$",
    r"(?im)^-?\s*review_status:\s*.*$",
    r"(?im)^-?\s*grounded:\s*.*$",
    r"(?im)^-?\s*grounding_mode:\s*.*$",
    r"(?im)^-?\s*confidence:\s*.*$",
    r"(?im)^source id:\s*.*$",
    r"(?im)^source title:\s*.*$",
    r"(?im)^chunk id:\s*.*$",
]

_PROVIDER_ERROR_PATTERNS = [
    r"incorrect api key provided",
    r"invalid_api_key",
    r"sk-proj-",
    r"status:\s*401",
    r"error code:\s*401",
    r"invalid_request_error",
    r"\bopenai\b",
    r"\bapi key\b",
]

_CLEAR_INTERNAL_MARKERS = [
    "candidate 1",
    "candidate 2",
    "candidate 3",
    "grounded basis",
    "grounding context",
    "grounding summary",
    "strict rules",
    "question classification",
    "you are answering as",
    "best supported answer",
    "based on the strongest available",
    "no evidence provided",
]

_SOURCE_PREFIX_RE = re.compile(r"(?im)^source:\s*")


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
        "candidate_id": getattr(candidate, "candidate_id", None),
        "canonical_key": getattr(candidate, "canonical_key", None),
        "topic": getattr(candidate, "topic", None),
        "intent_type": getattr(candidate, "intent_type", None),
        "jurisdiction": getattr(candidate, "jurisdiction", None),
        "lang": getattr(candidate, "lang", None),
        "trust_score": getattr(candidate, "trust_score", None),
        "source_authority_score": getattr(candidate, "source_authority_score", None),
        "similarity": getattr(candidate, "similarity", None),
        "match_type": getattr(candidate, "match_type", None),
        "rank_score": getattr(candidate, "rank_score", None),
        "review_status": getattr(candidate, "review_status", None),
    }


def _clean_lines(text: str) -> List[str]:
    raw = _safe_str(text)
    if not raw:
        return []

    lines = [ln.rstrip() for ln in raw.splitlines()]
    cleaned: List[str] = []
    blank_streak = 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            blank_streak += 1
            if blank_streak <= 1:
                cleaned.append("")
            continue

        blank_streak = 0
        cleaned.append(stripped)

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
    if _SOURCE_PREFIX_RE.match(last):
        return lines[:-1], last

    return lines, None


def _remove_known_internal_sections(text: str) -> str:
    cleaned = _safe_str(text)
    if not cleaned:
        return ""

    for pattern in _INTERNAL_HEADER_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned)

    for pattern in _INTERNAL_FIELD_LINE_PATTERNS:
        cleaned = re.sub(pattern, "", cleaned)

    return cleaned.strip()


def _sanitize_answer_text(text: str) -> str:
    cleaned = _remove_known_internal_sections(text)
    if not cleaned:
        return ""

    lines = _clean_lines(cleaned)
    filtered: List[str] = []

    for line in lines:
        lower = line.lower().strip()

        if any(re.search(pattern, lower, flags=re.I) for pattern in _PROVIDER_ERROR_PATTERNS):
            continue

        if lower.startswith("candidate ") and lower.endswith(":"):
            continue

        if lower in {
            "grounded basis:",
            "grounding context:",
            "grounding summary:",
            "strict rules:",
            "question classification:",
            "evidence:",
            "debug:",
            "system prompt:",
            "prompt:",
        }:
            continue

        filtered.append(line)

    return "\n".join(_clean_lines("\n".join(filtered))).strip()


def _count_internal_markers(text: str) -> int:
    raw = _safe_str(text).lower()
    if not raw:
        return 0

    count = 0
    for marker in _CLEAR_INTERNAL_MARKERS:
        if marker in raw:
            count += 1
    return count


def _has_provider_error(text: str) -> bool:
    raw = _safe_str(text)
    if not raw:
        return False
    return any(re.search(pattern, raw, flags=re.I) for pattern in _PROVIDER_ERROR_PATTERNS)


def looks_like_internal_or_broken_answer(text: str) -> bool:
    raw = _safe_str(text)
    if not raw:
        return True

    lower = raw.lower()

    if _has_provider_error(raw):
        return True

    marker_count = _count_internal_markers(lower)
    if marker_count >= 2:
        return True

    if "candidate 1" in lower and "candidate 2" in lower:
        return True

    if "trust_score" in lower and "similarity" in lower:
        return True

    if "grounding context" in lower and "strict rules" in lower:
        return True

    return False


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


def _fallback_unknown() -> str:
    return "I do not yet have enough reliable guidance in the system to answer that accurately."


def _format_definition(text: str) -> str:
    lines = _clean_lines(_sanitize_answer_text(text))
    lines, source_tail = _extract_source_tail(lines)

    if not lines:
        return _fallback_unknown()

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
        return _fallback_unknown()

    intro, steps = _split_intro_and_steps(lines)
    parts: List[str] = []

    if intro:
        parts.append("\n".join(intro[:2]))

    if steps:
        parts.append("Steps:\n" + "\n".join(steps))
    elif len(lines) > 1:
        numbered = [f"{i + 1}. {line}" for i, line in enumerate(lines[1:])]
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
        return _fallback_unknown()

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
        return _fallback_unknown()

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
        return _fallback_unknown()

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
        return _fallback_unknown()

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

    raw = _safe_str(answer_text)
    sanitized = _sanitize_answer_text(raw)

    if not sanitized:
        return _fallback_unknown()

    if looks_like_internal_or_broken_answer(raw) and not sanitized:
        return _fallback_unknown()

    if looks_like_internal_or_broken_answer(raw) and len(_clean_lines(sanitized)) <= 1:
        return _fallback_unknown()

    if intent_type == "definition":
        return _format_definition(sanitized)

    if intent_type in {"procedure", "how_to"}:
        return _format_procedure(sanitized)

    if intent_type in {"obligation", "eligibility"}:
        return _format_obligation(sanitized)

    if intent_type in {"calculation", "computation"}:
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
    raw_answer = _safe_str(
        answer_text or (candidate.get("answer") if isinstance(candidate, dict) else getattr(candidate, "answer", ""))
    )
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
