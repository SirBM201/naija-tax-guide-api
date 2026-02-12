# app/services/qa_cache_service.py
from __future__ import annotations
from typing import Optional, Dict, Any

from ..core.supabase_client import supabase
from .lang_service import normalize_lang
from datetime import datetime, timezone

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def get_cache_answer(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    ck = (canonical_key or "").strip()
    if not ck:
        return None
    lang = normalize_lang(lang)

    db = supabase()
    res = (
        db.table("qa_cache")
        .select("id, canonical_key, lang, answer, tags, priority, enabled, use_count, last_used_at")
        .eq("enabled", True)
        .eq("canonical_key", ck)
        .eq("lang", lang)
        .order("priority", desc=True)
        .limit(1)
        .execute()
    )
    if not res.data:
        return None

    row = res.data[0]

    # best-effort usage bump
    try:
        db.table("qa_cache").update(
            {"use_count": int(row.get("use_count") or 0) + 1, "last_used_at": _now_iso()}
        ).eq("id", row["id"]).execute()
    except Exception:
        pass

    return {
        "answer": (row.get("answer") or "").strip(),
        "canonical_key": row.get("canonical_key") or ck,
        "tags": row.get("tags"),
        "priority": int(row.get("priority") or 0),
        "source": "cache",
        "lang_used": row.get("lang") or lang,
    }

def upsert_cache_ai_answer(*, canonical_key: str, lang: str, answer: str, tags=None, priority: int = 0) -> None:
    ck = (canonical_key or "").strip()
    if not ck:
        return
    lang = normalize_lang(lang)
    ans = (answer or "").strip()
    if not ans:
        return

    db = supabase()
    payload: Dict[str, Any] = {
        "canonical_key": ck,
        "lang": lang,
        "answer": ans,
        "tags": tags,
        "priority": int(priority or 0),
        "source": "ai",
        "enabled": True,
        "last_used_at": _now_iso(),
    }

    # upsert using your UNIQUE(canonical_key, lang)
    try:
        db.table("qa_cache").upsert(payload, on_conflict="canonical_key,lang").execute()
    except Exception:
        # fallback insert
        try:
            db.table("qa_cache").insert(payload).execute()
        except Exception:
            pass
