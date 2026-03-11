from __future__ import annotations

from typing import List

from app.schemas.ask_models import QueryClassification, RetrievalCandidate
from .retrieval_exact import retrieve_exact_candidates
from .retrieval_keyword import retrieve_keyword_candidates
from .retrieval_semantic import retrieve_semantic_candidates
from .retrieval_sources import retrieve_source_candidates


def gather_candidates(classification: QueryClassification) -> List[RetrievalCandidate]:
    out: List[RetrievalCandidate] = []

    out.extend(retrieve_exact_candidates(classification))
    out.extend(retrieve_keyword_candidates(classification))
    out.extend(retrieve_semantic_candidates(classification))
    out.extend(retrieve_source_candidates(classification))

    return out
