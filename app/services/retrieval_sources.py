from __future__ import annotations

from typing import List

from app.schemas.ask_models import QueryClassification, RetrievalCandidate


def retrieve_source_candidates(classification: QueryClassification) -> List[RetrievalCandidate]:
    # Placeholder for future official source chunk retrieval.
    # Later this will search source_chunks table or official document index.
    return []
