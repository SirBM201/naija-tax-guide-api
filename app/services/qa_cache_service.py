# app/services/qa_cache_service.py
from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timezone

from ..core.supabase_client import supabase
from .response_refiner import looks_like_ai_failure


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _clean(s: str) -> str:
    return (s or "").strip()


def _norm_lang(lang: str) -> str:
    l = (lang or "en").strip().lower()
    return l or "en"


# ============================================================
# New-style API (canonical_key primary)
# ============================================================
def get_cache_answer(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    Preferred resolver:
      SELECT best enabled row by (canonical_key, lang)
    Returns: {answer, lang_used, canonical_key, source, id?}
    """
    canonical_key = _clean(canonical_key)
    lang = _norm_lang(lang)
    if not canonical_key:
        return None

    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id,canonical_key,lang,answer,source,priority,enabled,last_used_at")
            .eq("canonical_key", canonical_key)
            .eq("lang", lang)
            .eq("enabled", True)
            .order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return None

        row = rows[0] or {}
        ans = _clean(row.get("answer") or "")
        if not ans:
            return None
        if looks_like_ai_failure(ans):
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


def upsert_cache_ai_answer(*, canonical_key: str, lang: str, answer: str, tags=None, priority: int = 0) -> None:
    """
    Upsert AI answer only. Safe to call repeatedly (idempotent if unique index exists).
    """
    canonical_key = _clean(canonical_key)
    lang = _norm_lang(lang)
    answer = _clean(answer)

    if not canonical_key or not answer:
        return
    if looks_like_ai_failure(answer):
        return

    payload: Dict[str, Any] = {
        "canonical_key": canonical_key,
        "lang": lang,
        "answer": answer,
        "source": "ai",
        "enabled": True,
        "priority": int(priority or 0),
        "last_used_at": _now_utc().isoformat(),
    }
    if tags is not None:
        payload["tags"] = tags

    try:
        # Requires UNIQUE(canonical_key, lang) for perfect idempotency.
        supabase().table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()
    except Exception:
        # best-effort fallback insert
        try:
            supabase().table("qa_cache").insert(payload).execute()
        except Exception:
            pass


# ============================================================
# Backward-compatible API (older ask_service imports)
# ============================================================
def find_cached_answer(
    normalized_question: Optional[str] = None,
    lang: str = "en",
    *,
    canonical_key: Optional[str] = None,
    max_results: int = 1,
) -> Optional[Dict[str, Any]]:
    """
    Backward-compatible cache lookup.

    Supports BOTH:
      - find_cached_answer(normalized_question, lang, max_results=?)
      - find_cached_answer(canonical_key=..., normalized_question=..., lang=...)

    Ranking:
      - If canonical_key exists -> prefer it
      - Else -> use normalized_question
    """
    lang = _norm_lang(lang)
    canonical_key = _clean(canonical_key or "")
    normalized_question = _clean(normalized_question or "")

    try:
        q = (
            supabase()
            .table("qa_cache")
            .select("id,canonical_key,normalized_question,lang,answer,source,priority,enabled,last_used_at")
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
        rows = getattr(res, "data", None) or []
        if not rows:
            return None

        row = rows[0] or {}
        ans = _clean(row.get("answer") or "")
        if not ans:
            return None
        if looks_like_ai_failure(ans):
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


def touch_cache_best_effort(row_id: str) -> None:
    """
    Best-effort usage bump so your ordering stays good.
    Works even if you don't have RPC.
    """
    row_id = _clean(row_id)
    if not row_id:
        return

    # RPC if present
    try:
        supabase().rpc("touch_qa_cache", {"p_id": row_id}).execute()
        return
    except Exception:
        pass

    # Fallback update
    try:
        got = supabase().table("qa_cache").select("use_count").eq("id", row_id).limit(1).execute()
        cur = 0
        rows = getattr(got, "data", None) or []
        if rows:
            cur = int(rows[0].get("use_count") or 0)

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
    canonical_key: Optional[str] = None,
    priority: int = 0,
    tags=None,
) -> None:
    """
    Old signature compatibility.
    You decided: cache ONLY AI answers. So this enforces that.

    Stores:
      - canonical_key if provided
      - normalized_question (helpful for old lookups)
    """
    normalized_question = _clean(normalized_question)
    answer = _clean(answer)
    lang = _norm_lang(lang)
    canonical_key = _clean(canonical_key or "")

    if not answer:
        return
    if looks_like_ai_failure(answer):
        return

    payload: Dict[str, Any] = {
        "answer": answer,
        "source": "ai",
        "enabled": True,
        "priority": int(priority or 0),
        "lang": lang,
        "last_used_at": _now_utc().isoformat(),
    }
    if normalized_question:
        payload["normalized_question"] = normalized_question
    if canonical_key:
        payload["canonical_key"] = canonical_key
    if tags is not None:
        payload["tags"] = tags

    # Prefer conflict on canonical_key+lang if canonical_key present
    try:
        if canonical_key:
            supabase().table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()
        else:
            # fallback uniqueness by normalized_question+lang if you have that index
            supabase().table("qa_cache").upsert(payload, on_conflict="normalized_question,lang").execute()
    except Exception:
        # best-effort insert
        try:
            supabase().table("qa_cache").insert(payload).execute()
        except Exception:
            pass
