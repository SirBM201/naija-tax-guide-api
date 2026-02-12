# app/services/qa_cache_service.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from ..core.supabase_client import supabase


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def get_cache_answer(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    Fetch the best cache answer for (canonical_key, lang).
    Returns:
      { id?, answer, lang_used, canonical_key, source="cache" }
    """
    canonical_key = (canonical_key or "").strip()
    lang = (lang or "en").strip().lower() or "en"
    if not canonical_key:
        return None

    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("id, canonical_key, lang, answer, source, priority")
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
        ans = (row.get("answer") or "").strip()
        if not ans:
            return None

        return {
            "id": row.get("id"),
            "answer": ans,
            "lang_used": (row.get("lang") or lang),
            "canonical_key": canonical_key,
            "source": "cache",
        }
    except Exception:
        return None


def get_cache_answer_en_fallback(canonical_key: str) -> Optional[Dict[str, Any]]:
    return get_cache_answer(canonical_key, "en")


def upsert_cache_ai_answer(
    *,
    canonical_key: str,
    lang: str,
    answer: str,
    tags: Optional[List[str]] = None,
    priority: int = 0,
) -> None:
    """
    Upsert AI answer into qa_cache under unique (canonical_key, lang).
    Uses minimal columns to avoid schema mismatch.
    """
    canonical_key = (canonical_key or "").strip()
    lang = (lang or "en").strip().lower() or "en"
    answer = (answer or "").strip()
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


def touch_cache_best_effort(cache_id: str) -> None:
    """
    Best-effort usage touch. We don't assume exact schema.
    Tries to update last_used_at and bump hit_count if those columns exist.
    """
    cache_id = (cache_id or "").strip()
    if not cache_id:
        return

    # 1) Try last_used_at
    try:
        supabase().table("qa_cache").update({"last_used_at": _now_utc_iso()}).eq("id", cache_id).execute()
        return
    except Exception:
        pass

    # 2) Try updated_at (fallback)
    try:
        supabase().table("qa_cache").update({"updated_at": _now_utc_iso()}).eq("id", cache_id).execute()
    except Exception:
        pass

    # 3) Try hit_count increment (only if it exists) – do a read then write
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
    Wrapper used by ask_service.py.
    We intentionally ignore normalized_question to avoid schema mismatch
    unless your qa_cache table includes it (then you can add it later).
    """
    upsert_cache_ai_answer(canonical_key=canonical_key, lang=lang, answer=answer, priority=0)


# -------------------------------------------------------------------
# Backward-compat aliases (prevents ImportError when older modules
# still import old function names / signatures)
# -------------------------------------------------------------------

def find_cached_answer(
    *,
    canonical_key: str,
    normalized_question: str = "",
    lang: str = "en",
    max_results: int = 1,
) -> Optional[Dict[str, Any]]:
    """
    Backward-compatible adapter for older ask_service import/calls.
    Current cache lookup is keyed by (canonical_key, lang).
    """
    _ = (normalized_question, max_results)  # kept for signature compatibility
    return get_cache_answer(canonical_key, lang)
