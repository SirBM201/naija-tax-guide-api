from __future__ import annotations
from typing import Optional, Dict, Any
from ..core.supabase_client import supabase

LIB_LANG_COL = {
    "en": "answer_en",
    "yo": "answer_yoruba",   # adjust if your column is answer_yo
    "ig": "answer_igbo",     # adjust if your column is answer_ig
    "ha": "answer_hausa",    # adjust if your column is answer_ha
    "pcm": "answer_pidgin",  # adjust if your column is answer_pcm
}

def get_library_answer_by_canonical(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    if not canonical_key:
        return None

    col = LIB_LANG_COL.get(lang, "answer_en")

    # Always also pull English for fallback
    res = (
        supabase.table("qa_library")
        .select(f"id, canonical_key, {col}, answer_en, priority, enabled")
        .eq("canonical_key", canonical_key)
        .eq("enabled", True)
        .order("priority", desc=True)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    if not rows:
        return None

    row = rows[0]
    ans = row.get(col) or ""
    if not ans.strip():
        ans = row.get("answer_en") or ""

    if not ans.strip():
        return None

    return {
        "answer": ans.strip(),
        "lang_used": lang if (row.get(col) or "").strip() else "en",
        "canonical_key": row.get("canonical_key"),
        "source": "library",
    }
