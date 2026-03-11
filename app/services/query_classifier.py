from __future__ import annotations

import re
from app.schemas.ask_models import QueryClassification


def _normalize(text: str) -> str:
    t = (text or "").strip().lower()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[^\w\s]", "", t)
    return t.strip()


def _canonical_key(normalized: str) -> str:
    if not normalized:
        return "empty"
    return normalized[:120].replace(" ", "_")


def _detect_intent(q: str) -> str:
    ql = q.lower()

    if any(x in ql for x in ["what is", "meaning of", "stands for", "define"]):
        return "definition"

    if any(x in ql for x in ["how do i", "how to", "steps to", "register for", "process for"]):
        return "how_to"

    if any(x in ql for x in ["can i deduct", "deduct", "allowable expense", "expenses"]):
        return "deduction"

    if any(x in ql for x in ["calculate", "rate", "how much", "penalty", "due date"]):
        return "calculation"

    if any(x in ql for x in ["structure", "multi-branch", "cross border", "optimize", "advisory"]):
        return "advanced_advisory"

    return "general"


def _detect_topic(q: str) -> str:
    ql = q.lower()

    if "vat" in ql or "value added tax" in ql:
        return "vat"
    if "paye" in ql or "pay as you earn" in ql:
        return "paye"
    if "withholding" in ql or "wht" in ql:
        return "withholding_tax"
    if "company income tax" in ql or "cit" in ql:
        return "cit"
    if "freelancer" in ql or "sole proprietor" in ql:
        return "freelancer_tax"
    if "penalty" in ql or "fine" in ql:
        return "penalty"
    if "registration" in ql:
        return "registration"
    return "general"


def _detect_complexity(q: str) -> str:
    ql = q.lower()

    if any(x in ql for x in ["multi-branch", "cross-border", "group structure", "holding company", "state and federal"]):
        return "advanced"

    if len(ql.split()) > 12:
        return "intermediate"

    return "basic"


def _risk_level(intent_type: str, complexity: str) -> str:
    if complexity == "advanced" or intent_type in {"advanced_advisory", "calculation"}:
        return "high"
    if complexity == "intermediate":
        return "medium"
    return "low"


def _requires_clarification(intent_type: str, complexity: str) -> bool:
    if intent_type == "advanced_advisory":
        return True
    if complexity == "advanced":
        return True
    return False


def classify_query(question: str, lang: str = "en") -> QueryClassification:
    normalized = _normalize(question)
    intent_type = _detect_intent(normalized)
    topic = _detect_topic(normalized)
    complexity = _detect_complexity(normalized)

    return QueryClassification(
        raw_question=question,
        normalized_question=normalized,
        canonical_key=_canonical_key(normalized),
        intent_type=intent_type,
        topic=topic,
        jurisdiction="nigeria",
        complexity=complexity,
        risk_level=_risk_level(intent_type, complexity),
        requires_clarification=_requires_clarification(intent_type, complexity),
        lang=(lang or "en").strip().lower(),
    )
