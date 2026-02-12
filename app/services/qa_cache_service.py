# app/services/qa_cache_service.py
from __future__ import annotations

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from ..core.supabase_client import supabase


def _sb():
    """
    Your codebase sometimes uses supabase() and sometimes supabase.
    This makes it compatible with both patterns.
    """
    try:
        return supabase()  # type: ignore
    except TypeError:
        return supabase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def find_cached_answer(
    *,
    canonical_key: Optional[str] = None,
    normalized_question: Optional[str] = None,
    lang: str = "en",
    max_results: int = 1,
) -> Optional[Dict[str, Any]]:
    """
    Returns the best cache match for:
      1) (canonical_key, lang) if canonical_key provided
      2) else (normalized_question, lang)
    Respects enabled=true and prefers highest priority, newest created_at.
    """
    lang = (lang or "en").strip().lower()
    ckey = (canonical_key or "").strip()
    nq = (normalized_question or "").strip()

    if not ckey and not nq:
        return None

    client = _sb()

    q = (
        client.table("qa_cache")
        .select("id, canonical_key, normalized_question, lang, answer, source, priority, created_at")
        .eq("lang", lang)
        .eq("enabled", True)
        .order("priority", desc=True)
        .order("created_at", desc=True)
        .limit(int(max_results or 1))
    )

    if ckey:
        q = q.eq("canonical_key", ckey)
    else:
        q = q.eq("normalized_question", nq)

    res = q.execute()
    rows: List[Dict[str, Any]] = getattr(res, "data", None) or []
    if not rows:
        return None

    row = rows[0]
    ans = (row.get("answer") or "").strip()
    if not ans:
        return None

    return {
        "id": row.get("id"),
        "answer": ans,
        "lang_used": row.get("lang") or lang,
        "canonical_key": row.get("canonical_key") or ckey or None,
        "normalized_question": row.get("normalized_question") or nq or None,
        "source": row.get("source") or "cache",
    }


def touch_cache_best_effort(cache_id: str) -> None:
    """
    Best-effort usage touch:
      - last_used_at = now
      - use_count += 1 (best-effort; if we can't increment atomically we do read+write)
    """
    cid = (cache_id or "").strip()
    if not cid:
        return

    client = _sb()
    now = _now_iso()

    try:
        # Read current use_count (best effort)
        got = client.table("qa_cache").select("use_count").eq("id", cid).limit(1).execute()
        rows = getattr(got, "data", None) or []
        cur = 0
        if rows:
            cur = int(rows[0].get("use_count") or 0)

        client.table("qa_cache").update(
            {"last_used_at": now, "use_count": cur + 1}
        ).eq("id", cid).execute()
    except Exception:
        # At least try to update last_used_at
        try:
            client.table("qa_cache").update({"last_used_at": now}).eq("id", cid).execute()
        except Exception:
            pass


def upsert_ai_answer_to_cache_best_effort(
    *,
    canonical_key: Optional[str],
    normalized_question: str,
    answer: str,
    lang: str = "en",
    tags: Optional[list] = None,
    priority: int = 0,
) -> None:
    """
    Writes AI answers into qa_cache.
    - If canonical_key is present => upsert on (canonical_key, lang) (unique index exists where canonical_key is not null)
    - Else => upsert on (normalized_question, lang)
    """
    lang = (lang or "en").strip().lower()
    nq = (normalized_question or "").strip()
    ans = (answer or "").strip()
    ckey = (canonical_key or "").strip() or None

    if not nq or not ans:
        return

    payload: Dict[str, Any] = {
        "normalized_question": nq,
        "answer": ans,
        "lang": lang,
        "source": "ai",
        "enabled": True,
        "priority": int(priority or 0),
    }
    if tags is not None:
        payload["tags"] = tags
    if ckey:
        payload["canonical_key"] = ckey

    client = _sb()

    try:
        if ckey:
            client.table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()
        else:
            client.table("qa_cache").upsert(payload, on_conflict="normalized_question,lang").execute()
    except Exception:
        # If upsert fails (edge cases), do nothing (best-effort)
        pass


# -------------------------------------------------------------------
# Backward-compat aliases (prevents ImportError if older modules still import old names)
# -------------------------------------------------------------------

def get_cache_answer(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    return find_cached_answer(canonical_key=canonical_key, normalized_question=None, lang=lang, max_results=1)


def get_cache_answer_en_fallback(canonical_key: str) -> Optional[Dict[str, Any]]:
    return get_cache_answer(canonical_key, "en")


def upsert_cache_ai_answer(*, canonical_key: str, lang: str, answer: str, tags=None, priority: int = 0) -> None:
    return upsert_ai_answer_to_cache_best_effort(
        canonical_key=canonical_key,
        normalized_question=canonical_key,  # fallback if you only have key
        answer=answer,
        lang=lang,
        tags=tags,
        priority=priority,
    )
