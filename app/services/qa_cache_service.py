from __future__ import annotations
from typing import Optional, Dict, Any
from ..core.supabase_client import supabase

def get_cache_answer(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    if not canonical_key:
        return None
    res = (
        supabase.table("qa_cache")
        .select("canonical_key, lang, answer, source")
        .eq("canonical_key", canonical_key)
        .eq("lang", lang)
        .eq("enabled", True)
        .order("priority", desc=True)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    if not rows:
        return None
    ans = (rows[0].get("answer") or "").strip()
    if not ans:
        return None
    return {"answer": ans, "lang_used": rows[0].get("lang") or lang, "canonical_key": canonical_key, "source": "cache"}

def get_cache_answer_en_fallback(canonical_key: str) -> Optional[Dict[str, Any]]:
    return get_cache_answer(canonical_key, "en")

def upsert_cache_ai_answer(*, canonical_key: str, lang: str, answer: str, tags=None, priority: int = 0) -> None:
    payload = {
        "canonical_key": canonical_key,
        "lang": lang,
        "answer": answer,
        "source": "ai",
        "enabled": True,
        "priority": priority,
    }
    if tags is not None:
        payload["tags"] = tags

    supabase.table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()

# -------------------------------------------------------------------
# Backward-compat aliases (prevents ImportError when older modules
# still import old function names)
# -------------------------------------------------------------------

def find_cached_answer(*args, **kwargs):
    """
    Backward-compatible alias.
    Old code expects find_cached_answer(...).
    Newer code uses get_cache_answer(...).
    """
    return get_cache_answer(*args, **kwargs)

