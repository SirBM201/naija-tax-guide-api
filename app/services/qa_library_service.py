# app/services/qa_library_service.py
from __future__ import annotations
from typing import Optional, Dict, Any, List

from ..core.supabase_client import supabase
from .lang_service import LANG_FALLBACK_ORDER, normalize_lang

LANG_COL = {
    "en": "answer_en",
    "yo": "answer_yoruba",
    "ig": "answer_igbo",
    "ha": "answer_hausa",
    "pcm": "answer_pidgin",
}

def get_library_answer_by_canonical(*, canonical_key: str, preferred_lang: str) -> Optional[Dict[str, Any]]:
    ck = (canonical_key or "").strip()
    if not ck:
        return None

    langs: List[str] = LANG_FALLBACK_ORDER(preferred_lang)

    # Pull one best row by priority
    resp = (
        supabase.table("qa_library")
        .select("id, canonical_key, priority, enabled, " + ",".join(LANG_COL.values()))
        .eq("canonical_key", ck)
        .eq("enabled", True)
        .order("priority", desc=True)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    rows = resp.data or []
    if not rows:
        return None

    row = rows[0]
    for l in langs:
        col = LANG_COL.get(normalize_lang(l), "answer_en")
        ans = (row.get(col) or "").strip()
        if ans:
            return {"answer": ans, "lang_used": normalize_lang(l), "canonical_key": ck}

    return None
