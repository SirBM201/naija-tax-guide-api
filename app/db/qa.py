# app/db/qa.py
from typing import Optional, Dict, Any, List
import logging
from datetime import datetime, timezone

from app.core.supabase_client import supabase
from app.core.text import normalize_question  # if your project uses another path, adjust import

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def library_get(normalized_q: str, lang: str = "en") -> Optional[Dict[str, Any]]:
    """
    Pull a best answer from qa_library by normalized_question + enabled + priority.
    """
    select_cols = "answer,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha,enabled,priority"
    res = (
        supabase.table("qa_library")
        .select(select_cols)
        .eq("normalized_question", normalized_q)
        .eq("enabled", True)
        .order("priority", desc=True)
        .limit(1)
        .execute()
    )

    rows = res.data or []
    if not rows:
        return None
    row = rows[0]

    # Prefer language-specific column if present
    lang_map = {
        "en": "answer_en",
        "pcm": "answer_pcm",
        "yo": "answer_yo",
        "ig": "answer_ig",
        "ha": "answer_ha",
    }
    col = lang_map.get(lang, "answer_en")
    answer = row.get(col) or row.get("answer")
    if answer:
        row["answer"] = answer
    return row


def cache_get(question: str) -> Optional[Dict[str, Any]]:
    nq = normalize_question(question)

    # IMPORTANT: normalized_question (NOT normalised_question)
    res = (
        supabase.table("qa_cache")
        .select("answer,enabled")
        .eq("normalized_question", nq)
        .eq("enabled", True)
        .limit(1)
        .execute()
    )

    rows = res.data or []
    return rows[0] if rows else None


def cache_put(question: str, answer: str, tags: Optional[List[str]] = None, source: str = "telegram") -> None:
    nq = normalize_question(question)

    payload: Dict[str, Any] = {
        "normalized_question": nq,  # IMPORTANT
        "answer": answer,
        "enabled": True,
        "source": source,
        "last_used_at": _now_iso(),
        "use_count": 1,
        "updated_at": _now_iso(),
    }
    if tags is not None:
        payload["tags"] = tags

    # If normalized_question is UNIQUE in your qa_cache table, this is correct.
    # If not unique, remove on_conflict.
    try:
        supabase.table("qa_cache").upsert(payload, on_conflict="normalized_question").execute()
    except Exception as e:
        logging.exception("cache_put failed: %s", e)
        # Do not crash production pipeline
        return
