# app/services/qa_library_service.py
from __future__ import annotations

from typing import Optional, Dict, Any, List

from ..core.supabase_client import supabase


def _sb():
    try:
        return supabase()  # type: ignore
    except TypeError:
        return supabase


def _pick_lang_answer(row: Dict[str, Any], lang: str) -> str:
    """
    Your qa_library has:
      answer (base),
      answer_en, answer_pcm/answer_pidgin, answer_yo/answer_yoruba,
      answer_ig/answer_igbo, answer_ha/answer_hausa
    We'll pick the best available for requested lang.
    """
    l = (lang or "en").strip().lower()

    # Normalize language codes you may send from frontend
    if l in ("en", "eng", "english"):
        candidates = ["answer_en", "answer"]
    elif l in ("pcm", "pidgin", "ng-pidgin"):
        candidates = ["answer_pcm", "answer_pidgin", "answer"]
    elif l in ("yo", "yoruba"):
        candidates = ["answer_yo", "answer_yoruba", "answer"]
    elif l in ("ig", "igbo"):
        candidates = ["answer_ig", "answer_igbo", "answer"]
    elif l in ("ha", "hausa"):
        candidates = ["answer_ha", "answer_hausa", "answer"]
    else:
        candidates = ["answer", "answer_en"]

    for c in candidates:
        v = (row.get(c) or "").strip()
        if v:
            return v
    return ""


def find_library_answer(
    *,
    canonical_key: Optional[str] = None,
    normalized_question: Optional[str] = None,
    lang: str = "en",
) -> Optional[Dict[str, Any]]:
    """
    Find best QA library answer (no AI cost).
    Priority:
      1) enabled=true AND canonical_key match (if provided)
      2) else enabled=true AND normalized_question match (if provided)
    Orders by priority desc, updated_at desc.
    """
    ckey = (canonical_key or "").strip()
    nq = (normalized_question or "").strip()
    if not ckey and not nq:
        return None

    client = _sb()

    sel = (
        "id, canonical_key, normalized_question, answer, "
        "answer_en, answer_pcm, answer_yo, answer_ig, answer_ha, "
        "answer_pidgin, answer_yoruba, answer_igbo, answer_hausa, "
        "priority, enabled, source, updated_at"
    )

    q = (
        client.table("qa_library")
        .select(sel)
        .eq("enabled", True)
        .order("priority", desc=True)
        .order("updated_at", desc=True)
        .limit(1)
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
    ans = _pick_lang_answer(row, lang).strip()
    if not ans:
        return None

    return {
        "id": row.get("id"),
        "answer": ans,
        "lang_used": (lang or "en").strip().lower(),
        "canonical_key": row.get("canonical_key") or ckey or None,
        "normalized_question": row.get("normalized_question") or nq or None,
        "source": row.get("source") or "library",
    }


# -------------------------------------------------------------------
# Backward-compat alias
# -------------------------------------------------------------------
def get_library_answer(*args, **kwargs):
    return find_library_answer(*args, **kwargs)
