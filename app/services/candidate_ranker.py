from __future__ import annotations

from typing import List

from app.schemas.ask_models import QueryClassification, RetrievalCandidate


MIN_TRUST = 0.78


def _intent_compatible(query_intent: str, cand_intent: str) -> bool:
    if query_intent == cand_intent:
        return True

    compatible = {
        "definition": {"definition", "general"},
        "how_to": {"how_to"},
        "deduction": {"deduction", "general"},
        "calculation": {"calculation"},
        "advanced_advisory": {"advanced_advisory"},
        "general": {"general", "definition", "how_to"},
    }
    return cand_intent in compatible.get(query_intent, set())


def _passes_filters(query: QueryClassification, cand: RetrievalCandidate) -> bool:
    if (cand.review_status or "").lower() != "approved":
        return False

    if float(cand.trust_score or 0) < MIN_TRUST:
        return False

    if cand.topic not in {query.topic, "general", "", None}:
        return False

    if not _intent_compatible(query.intent_type, cand.intent_type):
        return False

    if cand.jurisdiction not in {query.jurisdiction, "global", "", None}:
        return False

    return True


def _score(query: QueryClassification, cand: RetrievalCandidate) -> float:
    score = 0.0

    if cand.match_type == "exact":
        score += 40
    if cand.match_type == "canonical":
        score += 30
    if cand.canonical_key == query.canonical_key:
        score += 25
    if cand.topic == query.topic:
        score += 20
    if cand.intent_type == query.intent_type:
        score += 15
    if cand.jurisdiction == query.jurisdiction:
        score += 10

    score += float(cand.trust_score or 0) * 20
    score += float(cand.source_authority_score or 0) * 10
    score += float(cand.similarity or 0) * 15

    return score


def rank_candidates(query: QueryClassification, candidates: List[RetrievalCandidate]) -> List[RetrievalCandidate]:
    filtered = [c for c in candidates if _passes_filters(query, c)]

    for c in filtered:
        c.rank_score = _score(query, c)

    filtered.sort(key=lambda x: x.rank_score, reverse=True)
    return filtered
