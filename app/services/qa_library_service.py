# app/services/qa_library_service.py
from __future__ import annotations

from typing import Any, Dict, Optional
from ..core.supabase_client import supabase
from .response_refiner import looks_like_ai_failure


def _clean(s: str) -> str:
    return (s or "").strip()


def _norm_lang(lang: Optional[str]) -> str:
    l = (lang or "en").strip().lower()
    return l or "en"


def _pick_lang_answer(row: Dict[str, Any], lang: str) -> str:
    lang = _norm_lang(lang)

    # common aliases
    if lang in ("yo", "yoruba"):
        return _clean(row.get("answer_yo") or row.get("answer_yoruba") or "")
    if lang in ("ig", "igbo"):
        return _clean(row.get("answer_ig") or row.get("answer_igbo") or "")
    if lang in ("ha", "hausa"):
        return _clean(row.get("answer_ha") or row.get("answer_hausa") or "")
    if lang in ("pcm", "pidgin"):
        return _clean(row.get("answer_pcm") or row.get("answer_pidgin") or "")

    # default english
    return _clean(row.get("answer_en") or row.get("answer") or "")


def get_library_answer_by_canonical(canonical_key: str, lang: str) -> Optional[Dict[str, Any]]:
    canonical_key = _clean(canonical_key)
    lang = _norm_lang(lang)
    if not canonical_key:
        return None

    try:
        res = (
            supabase()
            .table("qa_library")
            .select("*")
            .eq("canonical_key", canonical_key)
            .eq("enabled", True)
            .order("priority", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None

        row = rows[0] or {}
        ans = _pick_lang_answer(row, lang)
        if not ans or looks_like_ai_failure(ans):
            return None

        return {
            "id": row.get("id"),
            "answer": ans,
            "canonical_key": row.get("canonical_key") or canonical_key,
            "lang_used": lang,
            "source": "library",
        }
    except Exception:
        return None


def find_library_answer(*, canonical_key: str, normalized_question: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    Compatibility wrapper for ask_service.
    Ranking:
      1) canonical_key match
      2) normalized_question match
    """
    canonical_key = _clean(canonical_key)
    normalized_question = _clean(normalized_question)
    lang = _norm_lang(lang)

    # 1) canonical
    hit = get_library_answer_by_canonical(canonical_key, lang)
    if hit:
        return hit

    # 2) normalized question fallback
    if not normalized_question:
        return None

    try:
        res = (
            supabase()
            .table("qa_library")
            .select("*")
            .eq("normalized_question", normalized_question)
            .eq("enabled", True)
            .order("priority", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None

        row = rows[0] or {}
        ans = _pick_lang_answer(row, lang)
        if not ans or looks_like_ai_failure(ans):
            return None

        return {
            "id": row.get("id"),
            "answer": ans,
            "canonical_key": row.get("canonical_key") or canonical_key or None,
            "lang_used": lang,
            "source": "library",
        }
    except Exception:
        return None
