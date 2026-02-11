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
    nq = (normalized_question or "").strip()
    l = (lang or "en").strip().lower()
    if not nq:
        return None

    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id,answer,source,priority,lang,enabled,last_used_at")
            .eq("normalized_question", nq)
            .eq("lang", l)
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
            if looks_like_ai_failure(ans):
                return None
            return row
    except Exception:
        pass
    return None


def touch_cache_best_effort(row_id: str) -> None:
    rid = (row_id or "").strip()
    if not rid:
        return

    # Prefer atomic RPC if present
    try:
        supabase().rpc("touch_qa_cache", {"p_id": rid}).execute()
        return
    except Exception:
        pass

    # fallback (best effort)
    try:
        got = supabase().table("qa_cache").select("use_count").eq("id", rid).limit(1).execute()
        cur = 0
        if got.data:
            cur = int(got.data[0].get("use_count") or 0)

        supabase().table("qa_cache").update(
            {"use_count": cur + 1, "last_used_at": _now_utc().isoformat()}
        ).eq("id", rid).execute()
    except Exception:
        pass


def upsert_ai_answer_to_cache_best_effort(normalized_question: str, answer: str, lang: str) -> None:
    """
    Writes ONLY good answers. If answer looks like failure => don't cache.
    """
    nq = (normalized_question or "").strip()
    ans = (answer or "").strip()
    l = (lang or "en").strip().lower()

    if not nq or not ans:
        return
    if looks_like_ai_failure(ans):
        return

    now_iso = _now_utc().isoformat()

    try:
        existing = (
            supabase()
            .table("qa_cache")
            .select("id")
            .eq("normalized_question", nq)
            .eq("lang", l)
            .limit(1)
            .execute()
        )

        if existing.data:
            row_id = existing.data[0]["id"]
            supabase().table("qa_cache").update(
                {
                    "answer": ans,
                    "source": "ai",
                    "enabled": True,
                    "last_used_at": now_iso,
                }
            ).eq("id", row_id).execute()
            return

        supabase().table("qa_cache").insert(
            {
                "normalized_question": nq,
                "answer": ans,
                "tags": [],
                "use_count": 0,
                "last_used_at": now_iso,
                "created_at": now_iso,
                "source": "ai",
                "enabled": True,
                "priority": 0,
                "lang": l,
            }
        ).execute()
    except Exception:
        pass
