# app/services/qa_library_service.py
from __future__ import annotations
from typing import Optional, Dict, Any, List

from ..core.supabase_client import supabase
from .lang_service import normalize_lang

_LANG_COL_CANDIDATES = {
    "en": ["answer_en", "answer"],
    "pcm": ["answer_pcm", "answer_pidgin"],
    "yo": ["answer_yo", "answer_yoruba"],
    "ig": ["answer_ig", "answer_igbo"],
    "ha": ["answer_ha", "answer_hausa"],
}

def _pick_answer(row: Dict[str, Any], lang: str) -> Optional[str]:
    lang = normalize_lang(lang)
    for col in _LANG_COL_CANDIDATES.get(lang, []):
        v = row.get(col)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # fallback to english if requested lang missing
    for col in _LANG_COL_CANDIDATES["en"]:
        v = row.get(col)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def get_library_answer_by_canonical(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    Returns:
      { answer, canonical_key, tags, priority, source='library', lang_used }
    """
    ck = (canonical_key or "").strip()
    if not ck:
        return None

    db = supabase()

    # select minimal + all language columns (safe)
    select_cols: List[str] = [
        "id", "canonical_key", "enabled", "priority", "tags",
        "answer_en", "answer_pcm", "answer_yo", "answer_ig", "answer_ha",
        "answer_pidgin", "answer_yoruba", "answer_igbo", "answer_hausa",
        "answer",
    ]

    res = (
        db.table("qa_library")
        .select(",".join(select_cols))
        .eq("enabled", True)
        .eq("canonical_key", ck)
        .order("priority", desc=True)
        .limit(1)
        .execute()
    )

    if not res.data:
        return None

    row = res.data[0]
    ans = _pick_answer(row, lang)
    if not ans:
        return None

    used_lang = normalize_lang(lang)
    # if fallback used, tell the caller
    if used_lang != "en":
        # check if we truly had requested lang
        requested_ans = None
        for col in _LANG_COL_CANDIDATES.get(used_lang, []):
            v = row.get(col)
            if isinstance(v, str) and v.strip():
                requested_ans = v.strip()
                break
        if not requested_ans:
            used_lang = "en"

    return {
        "answer": ans,
        "canonical_key": row.get("canonical_key") or ck,
        "tags": row.get("tags"),
        "priority": int(row.get("priority") or 0),
        "source": "library",
        "lang_used": used_lang,
    }
