# app/db/qa.py
from typing import Optional, Dict, Any
from postgrest.exceptions import APIError

from app.core.text import normalize_question
from app.core.supabase_client import supabase


def _try_cache_get_by_column(col_name: str, norm_q: str) -> Optional[Dict[str, Any]]:
    res = (
        supabase()
        .table("qa_cache")
        .select("answer,enabled")
        .eq(col_name, norm_q)
        .eq("enabled", True)
        .limit(1)
        .execute()
    )
    data = res.data or []
    return data[0] if data else None


def cache_get(question: str) -> Optional[str]:
    """
    Returns cached answer string if found, else None.
    Never raises due to schema mismatch.
    """
    norm_q = normalize_question(question)

    # Prefer US spelling (your DB hint shows this exists)
    try:
        row = _try_cache_get_by_column("normalized_question", norm_q)
        if row and row.get("enabled"):
            return row.get("answer")
        return None
    except APIError:
        # Fallback: UK spelling (in case older schema exists somewhere)
        try:
            row = _try_cache_get_by_column("normalised_question", norm_q)
            if row and row.get("enabled"):
                return row.get("answer")
            return None
        except APIError:
            # If cache table is misconfigured, treat as cache miss (do not crash app)
            return None


def cache_put(question: str, answer: str) -> None:
    """
    Upserts into qa_cache using normalized_question.
    If table/column mismatched, it fails silently (does not crash request).
    """
    norm_q = normalize_question(question)
    payload = {
        "normalized_question": norm_q,
        "answer": answer,
        "enabled": True,
    }
    try:
        supabase().table("qa_cache").upsert(payload, on_conflict="normalized_question").execute()
        return
    except APIError:
        # Fallback attempt
        payload2 = {
            "normalised_question": norm_q,
            "answer": answer,
            "enabled": True,
        }
        try:
            supabase().table("qa_cache").upsert(payload2, on_conflict="normalised_question").execute()
        except APIError:
            return


def library_get(question: str, lang: str = "en") -> Optional[str]:
    """
    Pull from qa_library table first.
    Expected schema (recommended):
      normalized_question, enabled, priority, answer_en, answer
    """
    norm_q = normalize_question(question)

    select_cols = "answer_en,answer,enabled,priority"
    try:
        res = (
            supabase()
            .table("qa_library")
            .select(select_cols)
            .eq("normalized_question", norm_q)
            .eq("enabled", True)
            .order("priority", desc=True)
            .limit(1)
            .execute()
        )
        row = (res.data or [None])[0]
        if not row:
            return None
        if lang == "en":
            return row.get("answer_en") or row.get("answer")
        return row.get("answer") or row.get("answer_en")
    except APIError:
        # If your column differs, you can add another fallback here later
        return None
