# app/services/retrieval_service.py
from __future__ import annotations

from typing import Dict, Any, List

from .retrieval_exact import retrieve_exact_candidates
from .retrieval_keyword import retrieve_keyword_candidates
from .retrieval_semantic import retrieve_semantic_candidates
from .retrieval_sources import retrieve_source_candidates


def gather_candidates(classification: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    out.extend(retrieve_exact_candidates(classification))
    out.extend(retrieve_keyword_candidates(classification))
    out.extend(retrieve_semantic_candidates(classification))
    out.extend(retrieve_source_candidates(classification))

    return out
