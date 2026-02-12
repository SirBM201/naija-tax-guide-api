# app/services/qa_cache_service.py
from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timezone

from ..core.supabase_client import supabase
from .response_refiner import looks_like_ai_failure


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def find_cached_answer(
    *,
    canonical_key: str,
    normalized_question: str,
    lang: str,
    max_results: int = 1
) -> Optional[Dict[str, Any]]:
    """
    Returns a single best cached row or None.
    Ignores poisoned cache answers.
    Priority:
      1) canonical_key + lang
      2) normalized_question + lang
    """
    db = supabase()
    canonical_key = (canonical_key or "").strip()
    normalized_question = (normalized_question or "").strip()
    lang = (lang or "en").strip().lower()

    def _valid_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ans = (row.get("answer") or "").strip()
        if not ans:
            return None
        if looks_like_ai_failure(ans):
            return None
        return row

    # 1) canonical match
    if canonical_key:
        try:
            res = (
                db.table("qa_cache")
                .select("id,answer,source,priority,lang,enabled,last_used_at,use_count,canonical_key,normalized_question")
                .eq("canonical_key", canonical_key)
                .eq("lang", lang)
                .eq("enabled", True)
                .order("priority", desc=True)
                .order("last_used_at", desc=True)
                .limit(int(max_results or 1))
                .execute()
            )
            if res.data:
                v = _valid_row(res.data[0])
                if v:
                    return v
        except Exception:
            pass

    # 2) fallback normalized match
    if normalized_question:
        try:
            res = (
                db.table("qa_cache")
                .select("id,answer,source,priority,lang,enabled,last_used_at,use_count,canonical_key,normalized_question")
                .eq("normalized_question", normalized_question)
                .eq("lang", lang)
                .eq("enabled", True)
                .order("priority", desc=True)
                .order("last_used_at", desc=True)
                .limit(int(max_results or 1))
                .execute()
            )
            if res.data:
                v = _valid_row(res.data[0])
                if v:
                    return v
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
    *,
    canonical_key: str,
    normalized_question: str,
    answer: str,
    lang: str
) -> None:
    """
    Writes ONLY AI answers (good answers only).
    Stores ONLY canonical_key + normalized_question + answer (as requested).
    """
    canonical_key = (canonical_key or "").strip()
    normalized_question = (normalized_question or "").strip()
    answer = (answer or "").strip()
    lang = (lang or "en").strip().lower()

    if not canonical_key or not answer:
        return
    if looks_like_ai_failure(answer):
        return

    now_iso = _now_utc().isoformat()
    db = supabase()

    try:
        # Try update existing by canonical_key+lang first
        existing = (
            db.table("qa_cache")
            .select("id")
            .eq("canonical_key", canonical_key)
            .eq("lang", lang)
            .limit(1)
            .execute()
        )

        if existing.data:
            row_id = existing.data[0]["id"]
            db.table("qa_cache").update(
                {
                    "answer": answer,
                    "source": "ai",
                    "enabled": True,
                    "last_used_at": now_iso,
                    "normalized_question": normalized_question,
                }
            ).eq("id", row_id).execute()
            return

        # Insert new
        db.table("qa_cache").insert(
            {
                "canonical_key": canonical_key,
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
