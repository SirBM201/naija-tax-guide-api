# app/db/qa.py
from typing import Optional
from app.db.supabase_client import get_supabase

def library_get(question: str, lang: str) -> Optional[str]:
    sb = get_supabase()
    q = (question or "").strip()
    if not q:
        return None

    # Expecting: qa_library(question text, answer text, optional lang)
    # If your schema differs, tell me the exact column names and I’ll align it.
    resp = (
        sb.table("qa_library")
        .select("answer,lang,question")
        .eq("question", q)
        .limit(1)
        .execute()
    )
    rows = getattr(resp, "data", None) or []
    if not rows:
        return None
    row = rows[0]
    return row.get("answer") or None

def cache_get(question: str) -> Optional[str]:
    sb = get_supabase()
    q = (question or "").strip()
    if not q:
        return None

    resp = (
        sb.table("qa_cache")
        .select("answer,question")
        .eq("question", q)
        .limit(1)
        .execute()
    )
    rows = getattr(resp, "data", None) or []
    if not rows:
        return None
    return rows[0].get("answer") or None

def cache_set(question: str, answer: str) -> None:
    sb = get_supabase()
    q = (question or "").strip()
    a = (answer or "").strip()
    if not q or not a:
        return

    sb.table("qa_cache").upsert(
        {"question": q, "answer": a},
        on_conflict="question"
    ).execute()
