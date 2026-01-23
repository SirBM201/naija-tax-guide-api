# app/db/qa.py
from typing import Optional
from app.core.utils import normalize_question, now_utc, iso
from app.db.supabase_client import supabase

# Your schema notes:
# qa_cache: id, normalised_question, answer, tags, use_count, last_used_at, created_at, source, enabled, priority.
# qa_library: question, normalized_question, answer, tags, priority, enabled, source, + multi-language columns.

LANG_TO_COL = {
    "en": "answer_en",
    "pcm": "answer_pcm",
    "yo": "answer_yo",
    "ig": "answer_ig",
    "ha": "answer_ha",
}

def library_get(question: str, lang: str = "en") -> Optional[str]:
    nq = normalize_question(question)
    if not nq:
        return None

    col = LANG_TO_COL.get(lang, "answer_en")

    # Try language-specific first, fallback to "answer"
    q = (
        supabase()
        .table("qa_library")
        .select(f"{col},answer,enabled,priority")
        .eq("normalized_question", nq)
        .eq("enabled", True)
        .order("priority", desc=True)
        .limit(1)
        .execute()
    )

    rows = (q.data or [])
    if not rows:
        return None

    row = rows[0]
    val = row.get(col) or row.get("answer")
    return (val or None)

def cache_get(question: str) -> Optional[str]:
    nq = normalize_question(question)
    if not nq:
        return None

    q = (
        supabase()
        .table("qa_cache")
        .select("answer,enabled")
        .eq("normalised_question", nq)
        .eq("enabled", True)
        .limit(1)
        .execute()
    )
    rows = (q.data or [])
    if not rows:
        return None
    return rows[0].get("answer") or None

def cache_set(question: str, answer: str) -> None:
    nq = normalize_question(question)
    if not nq or not answer:
        return

    now = iso(now_utc())

    # Upsert by normalised_question if you have a unique constraint; if not, this still works as "insert new"
    supabase().table("qa_cache").upsert(
        {
            "normalised_question": nq,
            "answer": answer,
            "enabled": True,
            "source": "ai",
            "last_used_at": now,
            "created_at": now,
        },
        on_conflict="normalised_question",
    ).execute()
