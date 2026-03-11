from __future__ import annotations

from typing import List

from app.repositories.qa_cache_repo import find_by_canonical_key, find_exact_cache
from app.schemas.ask_models import QueryClassification, RetrievalCandidate


def _to_candidate(row: dict, match_type: str) -> RetrievalCandidate:
    return RetrievalCandidate(
        candidate_id=str(row.get("id") or ""),
        source_table="qa_cache",
        source_type=str(row.get("source") or "cache"),
        question=str(row.get("question") or ""),
        answer=str(row.get("answer") or ""),
        canonical_key=row.get("canonical_key"),
        normalized_question=row.get("normalized_question"),
        intent_type=str(row.get("intent_type") or "general"),
        topic=str(row.get("topic") or "general"),
        jurisdiction=str(row.get("jurisdiction") or "nigeria"),
        lang=str(row.get("lang") or "en"),
        trust_score=float(row.get("trust_score") or 0),
        review_status=str(row.get("review_status") or "pending"),
        source_authority_score=float(row.get("source_authority_score") or 0),
        similarity=1.0 if match_type == "exact" else 0.97,
        match_type=match_type,
    )


def retrieve_exact_candidates(classification: QueryClassification) -> List[RetrievalCandidate]:
    out: List[RetrievalCandidate] = []

    exact_rows = find_exact_cache(
        classification.normalized_question,
        lang=classification.lang,
        jurisdiction=classification.jurisdiction,
    )
    for row in exact_rows:
        out.append(_to_candidate(row, "exact"))

    key_rows = find_by_canonical_key(
        classification.canonical_key,
        lang=classification.lang,
        jurisdiction=classification.jurisdiction,
    )
    for row in key_rows:
        out.append(_to_candidate(row, "canonical"))

    return out
