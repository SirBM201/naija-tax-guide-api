# app/services/qa_cache_service.py
from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timezone

from ..core.supabase_client import supabase
from .response_refiner import looks_like_ai_failure


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(s: str) -> str:
    return (s or "").strip()


def _norm_lang(lang: Optional[str]) -> str:
    l = (lang or "en").strip().lower()
    return l or "en"


# ------------------------------------------------------------
# Preferred: canonical first
# ------------------------------------------------------------
def get_cache_answer(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    canonical_key = _clean(canonical_key)
    lang = _norm_lang(lang)
    if not canonical_key:
        return None

    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id,canonical_key,normalized_question,lang,answer,source,priority,enabled,use_count,last_used_at,created_at")
            .eq("canonical_key", canonical_key)
            .eq("lang", lang)
            .eq("enabled", True)
            .order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None

        row = rows[0] or {}
        ans = _clean(row.get("answer") or "")
        if not ans or looks_like_ai_failure(ans):
            return None

        return {
            "id": row.get("id"),
            "answer": ans,
            "lang_used": row.get("lang") or lang,
            "canonical_key": row.get("canonical_key") or canonical_key,
            "source": row.get("source") or "cache",
        }
    except Exception:
        return None


def get_cache_answer_en_fallback(canonical_key: str) -> Optional[Dict[str, Any]]:
    return get_cache_answer(canonical_key, "en")


# ------------------------------------------------------------
# Insert/Upsert AI answers only (your rule)
# ------------------------------------------------------------
def upsert_cache_ai_answer(
    *,
    canonical_key: str,
    normalized_question: str,
    lang: str,
    answer: str,
    tags=None,
    priority: int = 0,
) -> None:
    canonical_key = _clean(canonical_key)
    normalized_question = _clean(normalized_question)
    lang = _norm_lang(lang)
    answer = _clean(answer)

    if not normalized_question or not answer:
        return
    if looks_like_ai_failure(answer):
        return

    payload: Dict[str, Any] = {
        "normalized_question": normalized_question,  # REQUIRED (NOT NULL)
        "answer": answer,
        "lang": lang,
        "source": "ai",
        "enabled": True,
        "priority": int(priority or 0),
        "use_count": 0,           # REQUIRED (NOT NULL)
        "last_used_at": None,
        "created_at": _now_iso(), # REQUIRED (NOT NULL)
        "canonical_key": canonical_key or None,
    }
    if tags is not None:
        payload["tags"] = tags

    # IMPORTANT: on_conflict must match your DB unique constraint.
    # If you do NOT have a unique constraint yet, this will still work as insert-only fallback.
    try:
        if canonical_key:
            supabase().table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()
        else:
            supabase().table("qa_cache").upsert(payload, on_conflict="normalized_question,lang").execute()
    except Exception:
        try:
            supabase().table("qa_cache").insert(payload).execute()
        except Exception:
            pass


# ------------------------------------------------------------
# Backward-compat exports (ask_service imports these names)
# ------------------------------------------------------------
def find_cached_answer(
    *,
    canonical_key: Optional[str] = None,
    normalized_question: Optional[str] = None,
    lang: str = "en",
    max_results: int = 1,
) -> Optional[Dict[str, Any]]:
    """
    Ranking:
      1) canonical_key + lang
      2) normalized_question + lang
    """
    lang = _norm_lang(lang)
    canonical_key = _clean(canonical_key or "")
    normalized_question = _clean(normalized_question or "")

    try:
        q = (
            supabase()
            .table("qa_cache")
            .select("id,canonical_key,normalized_question,lang,answer,source,priority,enabled,use_count,last_used_at,created_at")
            .eq("lang", lang)
            .eq("enabled", True)
        )

        if canonical_key:
            q = q.eq("canonical_key", canonical_key)
        elif normalized_question:
            q = q.eq("normalized_question", normalized_question)
        else:
            return None

        res = (
            q.order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(int(max_results or 1))
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None

        row = rows[0] or {}
        ans = _clean(row.get("answer") or "")
        if not ans or looks_like_ai_failure(ans):
            return None

        return {
            "id": row.get("id"),
            "answer": ans,
            "lang_used": row.get("lang") or lang,
            "canonical_key": row.get("canonical_key") or canonical_key or None,
            "source": row.get("source") or "cache",
        }
    except Exception:
        return None


def touch_cache_best_effort(row_id: str) -> None:
    row_id = _clean(row_id)
    if not row_id:
        return

    try:
        got = supabase().table("qa_cache").select("use_count").eq("id", row_id).limit(1).execute()
        cur = 0
        rows = got.data or []
        if rows:
            cur = int(rows[0].get("use_count") or 0)

        supabase().table("qa_cache").update(
            {"use_count": cur + 1, "last_used_at": _now_iso()}
        ).eq("id", row_id).execute()
    except Exception:
        pass


def upsert_ai_answer_to_cache_best_effort(
    *,
    canonical_key: str,
    normalized_question: str,
    answer: str,
    lang: str,
    tags=None,
    priority: int = 0,
) -> None:
    upsert_cache_ai_answer(
        canonical_key=canonical_key,
        normalized_question=normalized_question,
        lang=lang,
        answer=answer,
        tags=tags,
        priority=priority,
    )
