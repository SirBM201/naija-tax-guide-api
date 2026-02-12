# app/services/qa_cache_service.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from ..core.supabase_client import supabase


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _norm_lang(lang: str) -> str:
    l = (lang or "en").strip().lower()
    return l or "en"


def _clean(s: str) -> str:
    return (s or "").strip()


# ------------------------------------------------------------
# Canonical Cache Read
# ------------------------------------------------------------
def get_cache_answer(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    Fetch the best enabled cache answer for (canonical_key, lang).
    Returns a dict shaped to satisfy ask_service usage:
      { id, answer, lang_used, canonical_key, source="cache" }
    """
    canonical_key = _clean(canonical_key)
    lang = _norm_lang(lang)

    if not canonical_key:
        return None

    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id, canonical_key, lang, answer, source, priority, created_at")
            .eq("canonical_key", canonical_key)
            .eq("lang", lang)
            .eq("enabled", True)
            .order("priority", desc=True)
            .order("created_at", desc=True)
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

        return {
            "id": row.get("id"),
            "answer": ans,
            "lang_used": row.get("lang") or lang,
            "canonical_key": canonical_key,
            "source": "cache",
        }
    except Exception:
        return None


def get_cache_answer_en_fallback(canonical_key: str) -> Optional[Dict[str, Any]]:
    return get_cache_answer(canonical_key, "en")


# ------------------------------------------------------------
# Canonical Cache Upsert (AI answers only)
# ------------------------------------------------------------
def upsert_cache_ai_answer(
    *,
    canonical_key: str,
    lang: str,
    answer: str,
    tags: Optional[List[str]] = None,
    priority: int = 0,
) -> None:
    """
    Upsert AI answer into qa_cache at unique (canonical_key, lang).
    Uses minimal columns (safe vs schema drift).
    """
    canonical_key = _clean(canonical_key)
    lang = _norm_lang(lang)
    answer = _clean(answer)

    if not canonical_key or not answer:
        return

    payload: Dict[str, Any] = {
        "canonical_key": canonical_key,
        "lang": lang,
        "answer": answer,
        "source": "ai",
        "enabled": True,
        "priority": int(priority or 0),
    }
    if tags is not None:
        payload["tags"] = tags

    try:
        supabase().table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()
    except Exception:
        # best-effort only
        pass


# ------------------------------------------------------------
# Best-effort tracking (must exist for ask_service import)
# ------------------------------------------------------------
def touch_cache_best_effort(cache_id: str) -> None:
    """
    Best-effort: mark a cache row as used.
    Tries common columns; ignores failures.
    """
    cache_id = _clean(cache_id)
    if not cache_id:
        return

    # Try last_used_at
    try:
        supabase().table("qa_cache").update({"last_used_at": _now_utc_iso()}).eq("id", cache_id).execute()
        return
    except Exception:
        pass

    # Try updated_at
    try:
        supabase().table("qa_cache").update({"updated_at": _now_utc_iso()}).eq("id", cache_id).execute()
    except Exception:
        pass

    # Try hit_count increment (read then write)
    try:
        got = supabase().table("qa_cache").select("hit_count").eq("id", cache_id).limit(1).execute()
        rows = getattr(got, "data", None) or []
        if not rows:
            return
        cur = int(rows[0].get("hit_count") or 0)
        supabase().table("qa_cache").update({"hit_count": cur + 1}).eq("id", cache_id).execute()
    except Exception:
        pass


def upsert_ai_answer_to_cache_best_effort(
    *,
    canonical_key: str,
    normalized_question: str,
    answer: str,
    lang: str,
) -> None:
    """
    Best-effort: store AI answer into cache.
    We keep normalized_question in the signature for compatibility,
    but we don't write it unless your table has such a column.
    """
    _ = normalized_question  # keep signature compatibility
    upsert_cache_ai_answer(canonical_key=canonical_key, lang=lang, answer=answer, priority=0)


# ------------------------------------------------------------
# Backward-compat adapter (must exist for ask_service import)
# ------------------------------------------------------------
def find_cached_answer(
    *,
    canonical_key: str,
    normalized_question: str = "",
    lang: str = "en",
    max_results: int = 1,
) -> Optional[Dict[str, Any]]:
    """
    Backward-compatible adapter for older ask_service calls.

    Your current cache lookup is by (canonical_key, lang),
    not by fuzzy normalized_question search.
    """
    _ = (normalized_question, max_results)  # signature compatibility only
    return get_cache_answer(canonical_key, lang)
