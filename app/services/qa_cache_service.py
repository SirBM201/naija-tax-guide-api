# app/services/qa_cache_service.py
from __future__ import annotations
from typing import Optional, Dict, Any, List
from ..core.supabase_client import supabase
from .lang_service import LANG_FALLBACK_ORDER, normalize_lang

def get_cache_answer(*, canonical_key: str, preferred_lang: str) -> Optional[Dict[str, Any]]:
    ck = (canonical_key or "").strip()
    if not ck:
        return None

    langs: List[str] = LANG_FALLBACK_ORDER(preferred_lang)

    # Try in order (cheap, fast, predictable)
    for l in langs:
        resp = (
            supabase.table("qa_cache")
            .select("id, canonical_key, lang, answer, enabled")
            .eq("canonical_key", ck)
            .eq("lang", normalize_lang(l))
            .eq("enabled", True)
            .order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = resp.data or []
        if rows and (rows[0].get("answer") or "").strip():
            return {"answer": rows[0]["answer"], "lang_used": rows[0]["lang"]}

    return None

def upsert_cache_ai_answer(*, canonical_key: str, lang: str, answer: str, tags=None, priority: int = 0) -> None:
    ck = (canonical_key or "").strip()
    l = normalize_lang(lang)
    ans = (answer or "").strip()
    if not ck or not ans:
        return

    payload = {
        "canonical_key": ck,
        "lang": l,
        "normalized_question": ck,   # you decided: store normalized_question + answer only (great)
        "answer": ans,
        "tags": tags or [],
        "priority": int(priority),
        "source": "ai",
        "enabled": True,
    }

    # ON CONFLICT requires your UNIQUE(canonical_key, lang)
    supabase.table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()
