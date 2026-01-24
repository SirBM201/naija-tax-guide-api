import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from app.db.supabase_client import supabase
from app.core.text import normalize_question

log = logging.getLogger(__name__)

def cache_get(question: str) -> Optional[Dict[str, Any]]:
    """
    Reads from qa_cache by normalized_question.
    Fail-safe: returns None on any error.
    """
    qn = normalize_question(question)
    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("answer, enabled")
            .eq("normalized_question", qn)
            .eq("enabled", True)
            .limit(1)
            .execute()
        )
        data = res.data or []
        return data[0] if data else None
    except Exception as e:
        log.exception("qa_cache cache_get error: %s", e)
        return None

def cache_put(question: str, answer: str, tags: Optional[List[str]] = None, source: str = "web") -> None:
    """
    Upsert into qa_cache using normalized_question as unique key.
    """
    qn = normalize_question(question)
    try:
        payload = {
            "normalized_question": qn,
            "answer": answer,
            "enabled": True,
            "tags": tags or [],
            "source": source,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        supabase().table("qa_cache").upsert(payload, on_conflict="normalized_question").execute()
    except Exception as e:
        log.exception("qa_cache cache_put error: %s", e)

def library_get(normalized_question: str, lang: str = "en") -> Optional[Dict[str, Any]]:
    """
    Reads from qa_library by normalized_question.
    """
    nq = (normalized_question or "").strip().lower()
    if not nq:
        return None

    try:
        # choose answer field based on lang
        # If you only maintain answer_en, it will still work.
        answer_field = "answer_en" if lang == "en" else "answer"

        res = (
            supabase()
            .table("qa_library")
            .select(f"{answer_field}, answer_en, answer, enabled, priority")
            .eq("normalized_question", nq)
            .eq("enabled", True)
            .order("priority", desc=True)
            .limit(1)
            .execute()
        )

        data = res.data or []
        if not data:
            return None

        row = data[0]
        # prefer requested lang, fallback to answer_en, then answer
        ans = row.get(answer_field) or row.get("answer_en") or row.get("answer")
        return {"answer": ans} if ans else None
    except Exception as e:
        log.exception("qa_library library_get error: %s", e)
        return None
