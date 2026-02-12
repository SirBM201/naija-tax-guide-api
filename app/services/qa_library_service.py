# app/services/qa_library_service.py
from __future__ import annotations

from typing import Any, Dict, Optional

from ..core.supabase_client import supabase
from .response_refiner import looks_like_ai_failure


def find_library_answer(normalized_question: str, lang: str = "en") -> Optional[Dict[str, Any]]:
    """
    Returns a single best qa_library row or None.

    IMPORTANT:
    - We do NOT write qa_library answers into qa_cache (space conservation).
    - We try to filter by lang/enabled if those columns exist, but gracefully fall back if not.
    """
    nq = (normalized_question or "").strip()
    if not nq:
        return None

    db = supabase()

    # Try the most specific query first (if columns exist)
    try:
        res = (
            db.table("qa_library")
            .select("id,answer,question,normalized_question,category,lang,enabled,updated_at,created_at")
            .eq("normalized_question", nq)
            .eq("lang", (lang or "en").strip().lower())
            .eq("enabled", True)
            .limit(1)
            .execute()
        )
        if res.data:
            row = res.data[0]
            ans = (row.get("answer") or "").strip()
            if ans and not looks_like_ai_failure(ans):
                return row
            return None
    except Exception:
        pass

    # Fall back: ignore lang/enabled (for schemas without those fields)
    try:
        res = (
            db.table("qa_library")
            .select("id,answer,question,normalized_question,category,updated_at,created_at")
            .eq("normalized_question", nq)
            .limit(1)
            .execute()
        )
        if res.data:
            row = res.data[0]
            ans = (row.get("answer") or "").strip()
            if ans and not looks_like_ai_failure(ans):
                return row
    except Exception:
        pass

    return None
