from __future__ import annotations

from typing import List

from app.repositories.qa_cache_repo import keyword_cache_search
from app.schemas.ask_models import QueryClassification, RetrievalCandidate


def retrieve_keyword_candidates(classification: QueryClassification) -> List[RetrievalCandidate]:
    rows = keyword_cache_search(
        topic=classification.topic,
        intent_type=classification.intent_type,
        lang=classification.lang,
        jurisdiction=classification.jurisdiction,
        limit=10,
    )

    out: List[RetrievalCandidate] = []
    for row in rows:
        out.append(
            RetrievalCandidate(
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
                similarity=0.72,
                match_type="keyword",
            )
        )
    return out
