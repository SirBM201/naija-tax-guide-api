# app/services/qa_cache_service.py
from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timezone

from ..core.supabase_client import supabase
from .response_refiner import looks_like_ai_failure


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def find_cached_answer(normalized_question: str, lang: str, *, max_results: int = 1) -> Optional[Dict[str, Any]]:
    """
    Returns a single best cached row or None.
    Also ignores poisoned cache answers (AI failures).
    """
    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id,answer,source,priority,lang,enabled,last_used_at")
            .eq("normalized_question", normalized_question)
            .eq("lang", lang)
            .eq("enabled", True)
            .order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(int(max_results or 1))
            .execute()
        )
        if res.data:
            row = res.data[0]
            ans = (row.get("answer") or "").strip()
            if not ans:
                return None
            # IMPORTANT: ignore poisoned cache entries
            if looks_like_ai_failure(ans):
                return None
            return row
    except Exception:
        pass
    return None


def touch_cache_best_effort(row_id: str) -> None:
    if not row_id:
        return

    # Prefer atomic RPC if present
    try:
        supabase().rpc("touch_qa_cache", {"p_id": row_id}).execute()
        return
    except Exception:
        pass

    # fallback (best effort)
    try:
        got = supabase().table("qa_cache").select("use_count").eq("id", row_id).limit(1).execute()
        cur = 0
        if got.data:
            cur = int(got.data[0].get("use_count") or 0)
        supabase().table("qa_cache").update(
            {"use_count": cur + 1, "last_used_at": _now_utc().isoformat()}
        ).eq("id", row_id).execute()
    except Exception:
        pass


def upsert_ai_answer_to_cache_best_effort(normalized_question: str, answer: str, lang: str) -> None:
    """
    Writes ONLY good answers. If answer looks like failure => don't cache.
    """
    normalized_question = (normalized_question or "").strip()
    answer = (answer or "").strip()
    lang = (lang or "en").strip().lower()

    if not normalized_question or not answer:
        return
    if looks_like_ai_failure(answer):
        return

    now_iso = _now_utc().isoformat()

    try:
        existing = (
            supabase()
            .table("qa_cache")
            .select("id")
            .eq("normalized_question", normalized_question)
            .eq("lang", lang)
            .limit(1)
            .execute()
        )

        if existing.data:
            row_id = existing.data[0]["id"]
            supabase().table("qa_cache").update(
                {
                    "answer": answer,
                    "source": "ai",
                    "enabled": True,
                    "last_used_at": now_iso,
                }
            ).eq("id", row_id).execute()
            return

        supabase().table("qa_cache").insert(
            {
                "normalized_question": normalized_question,
                "answer": answer,
                "tags": [],
                "use_count": 0,
                "last_used_at": now_iso,
                "created_at": now_iso,
                "source": "ai",
                "enabled": True,
                "priority": 0,
                "lang": lang,
            }
        ).execute()
    except Exception:
        pass
