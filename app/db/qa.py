# app/db/qa.py
from typing import Optional, Dict, Any, List
import logging
from datetime import datetime, timezone

from app.db.supabase_client import supabase
from app.core.utils import normalize_question

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def library_get(question: str, lang: str = "en") -> Optional[Dict[str, Any]]:
    nq = normalize_question(question)

    res = (
        supabase()
        .table("qa_library")
        .select("answer,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha,enabled,priority")
        .eq("normalized_question", nq)
        .eq("enabled", True)
        .order("priority", desc=True)
        .limit(1)
        .execute()
    )

    rows = res.data or []
    if not rows:
        return None

    row = rows[0]

    lang_map = {
        "en": "answer_en",
        "pcm": "answer_pcm",
        "yo": "answer_yo",
        "ig": "answer_ig",
        "ha": "answer_ha",
    }

    # Prefer language column if present; fallback to "answer"
    answer = row.get(lang_map.get(lang, "answer_en")) or row.get("answer")
    if answer:
        row["answer"] = answer

    return row

def cache_get(question: str) -> Optional[Dict[str, Any]]:
    nq = normalize_question(question)

    res = (
        supabase()
        .table("qa_cache")
        .select("answer,enabled")
        .eq("normalized_question", nq)   # ✅ correct column name
        .eq("enabled", True)
        .limit(1)
        .execute()
    )

    rows = res.data or []
    return rows[0] if rows else None

def cache_put(question: str, answer: str, tags: Optional[List[str]] = None, source: str = "telegram") -> None:
    nq = normalize_question(question)

    payload: Dict[str, Any] = {
        "normalized_question": nq,      # ✅ correct column name
        "answer": answer,
        "enabled": True,
        "source": source,
        "updated_at": _now_iso(),
    }
    if tags:
        payload["tags"] = tags

    try:
        supabase().table("qa_cache").upsert(payload, on_conflict="normalized_question").execute()
    except Exception as e:
        # Cache failures must never crash the app
        logging.exception("cache_put failed (ignored): %s", e)
