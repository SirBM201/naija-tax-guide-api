# app/services/qa_logging_service.py
from __future__ import annotations

from typing import Optional
from ..core.supabase_client import supabase


def log_qa_event_best_effort(
    *,
    account_id: str,
    mode: str,
    lang: str,
    question_raw: str,
    normalized_question: str,
    canonical_key: Optional[str],
    outcome: str,          # ok|blocked|error
    reason: Optional[str], # ai_credits_exhausted|validation_error|internal_error|...
    source: Optional[str], # cache|library|ai|None
    cache_hit: bool,
    library_hit: bool,
    ai_used: bool,
    ai_credit_cost: int,
    latency_ms: int,
) -> None:
    try:
        supabase().rpc("log_qa_event", {
            "p_account_id": account_id,
            "p_mode": mode,
            "p_lang": lang,
            "p_question_raw": question_raw,
            "p_normalized_question": normalized_question,
            "p_canonical_key": canonical_key,
            "p_outcome": outcome,
            "p_reason": reason,
            "p_source": source,
            "p_cache_hit": bool(cache_hit),
            "p_library_hit": bool(library_hit),
            "p_ai_used": bool(ai_used),
            "p_ai_credit_cost": int(ai_credit_cost or 0),
            "p_latency_ms": int(latency_ms or 0),
        }).execute()
    except Exception:
        return
