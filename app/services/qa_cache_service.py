# app/services/qa_cache_service.py
from __future__ import annotations

from typing import Optional, Dict, Any
from datetime import datetime, timezone

from ..core.supabase_client import supabase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def find_cached_answer(
    normalized_question: str,
    lang: str = "en",
    canonical_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    nq = (normalized_question or "").strip()
    if not nq:
        return None
    lang = (lang or "en").strip() or "en"

    try:
        if canonical_key and canonical_key.strip():
            ck = canonical_key.strip()
            res = (
                supabase().table("qa_cache")
                .select("*")
                .eq("enabled", True)
                .eq("canonical_key", ck)
                .eq("lang", lang)
                .order("priority", desc=True)
                .limit(1)
                .execute()
            )
            if getattr(res, "data", None):
                return res.data[0]

        res = (
            supabase().table("qa_cache")
            .select("*")
            .eq("enabled", True)
            .eq("normalized_question", nq)
            .eq("lang", lang)
            .order("priority", desc=True)
            .limit(1)
            .execute()
        )
        if getattr(res, "data", None):
            return res.data[0]
        return None
    except Exception:
        return None


def touch_cache_best_effort(cache_id: str) -> None:
    cid = (cache_id or "").strip()
    if not cid:
        return
    try:
        res = supabase().table("qa_cache").select("use_count").eq("id", cid).limit(1).execute()
        current = 0
        if getattr(res, "data", None):
            current = int(res.data[0].get("use_count") or 0)

        supabase().table("qa_cache").update(
            {"use_count": current + 1, "last_used_at": _now_iso()}
        ).eq("id", cid).execute()
    except Exception:
        return


def upsert_ai_answer_to_cache_best_effort(
    normalized_question: str,
    answer: str,
    tags: Optional[str] = None,
    source: str = "ai",
    lang: str = "en",
    canonical_key: Optional[str] = None,
    enabled: bool = True,
    priority: int = 0,
) -> None:
    nq = (normalized_question or "").strip()
    ans = (answer or "").strip()
    if not nq or not ans:
        return

    lang = (lang or "en").strip() or "en"
    payload: Dict[str, Any] = {
        "normalized_question": nq,
        "answer": ans,
        "tags": tags,
        "source": source,
        "enabled": bool(enabled),
        "priority": int(priority or 0),
        "lang": lang,
        "last_used_at": _now_iso(),
    }
    if canonical_key and canonical_key.strip():
        payload["canonical_key"] = canonical_key.strip()

    try:
        # canonical_key+lang preferred when present; else normalized_question+lang
        if payload.get("canonical_key"):
            supabase().table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()
        else:
            supabase().table("qa_cache").upsert(payload, on_conflict="normalized_question,lang").execute()
    except Exception:
        return
