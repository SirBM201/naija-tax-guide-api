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
    Ignores poisoned cache answers (AI failures).

    NOTE: This is runtime cache (AI + optionally curated if you ever insert manually).
    """
    nq = (normalized_question or "").strip()
    l = (lang or "en").strip().lower()
    if not nq:
        return None

    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id,answer,source,priority,lang,enabled,last_used_at,use_count,created_at")
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


def upsert_ai_answer_to_cache_best_effort(
    normalized_question: str,
    answer: str,
    lang: str,
    *,
    original_question: Optional[str] = None,
) -> None:
    """
    Writes ONLY good AI answers.
    If answer looks like failure => don't cache.
    If qa_cache has a `question` column, we store original_question too; otherwise we ignore it.
    """
    nq = (normalized_question or "").strip()
    ans = (answer or "").strip()
    l = (lang or "en").strip().lower()

    if not nq or not ans:
        return
    if looks_like_ai_failure(ans):
        return

    now_iso = _now_utc().isoformat()
    db = supabase()

    # Check if an entry already exists for this key
    try:
        existing = (
            db.table("qa_cache")
            .select("id")
            .eq("normalized_question", nq)
            .eq("lang", l)
            .limit(1)
            .execute()
        )
        if existing.data:
            row_id = existing.data[0]["id"]

            # Try updating WITH question (if column exists)
            payload_with_q = {
                "answer": ans,
                "source": "ai",
                "enabled": True,
                "last_used_at": now_iso,
            }
            if original_question:
                payload_with_q["question"] = original_question

            try:
                db.table("qa_cache").update(payload_with_q).eq("id", row_id).execute()
                return
            except Exception:
                # Fall back without question column
                db.table("qa_cache").update(
                    {
                        "answer": ans,
                        "source": "ai",
                        "enabled": True,
                        "last_used_at": now_iso,
                    }
                ).eq("id", row_id).execute()
                return

        # No existing row -> insert
        base_row = {
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

        # Try insert WITH question (if column exists)
        if original_question:
            row_with_q = dict(base_row)
            row_with_q["question"] = original_question
            try:
                db.table("qa_cache").insert(row_with_q).execute()
                return
            except Exception:
                pass

        # Fall back insert without question
        db.table("qa_cache").insert(base_row).execute()
    except Exception:
        pass
