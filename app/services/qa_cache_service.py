# app/services/qa_library_service.py
from __future__ import annotations

from typing import Optional, Dict, Any, List

from ..core.supabase_client import supabase


def _clean(s: str) -> str:
    return (s or "").strip()


def _norm_lang(lang: str) -> str:
    l = (lang or "en").strip().lower()
    return l or "en"


def _pick_answer_from_row(row: Dict[str, Any], lang: str) -> str:
    """
    Supports common schemas:
      - answer (single column)
      - answer_en / answer_yo / answer_ig / answer_ha / answer_pcm
      - answer_<lang>
    """
    lang = _norm_lang(lang)

    # 1) direct "answer"
    a = _clean(row.get("answer") or "")
    if a:
        return a

    # 2) per-language column answer_<lang>
    key = f"answer_{lang}"
    a = _clean(row.get(key) or "")
    if a:
        return a

    # 3) common Nigerian languages naming variations
    fallback_keys = {
        "yo": ["answer_yo", "answer_yoruba"],
        "ig": ["answer_ig", "answer_igbo"],
        "ha": ["answer_ha", "answer_hausa"],
        "pcm": ["answer_pcm", "answer_pigin", "answer_pidgin"],
        "en": ["answer_en", "answer_english"],
    }.get(lang, [])

    for k in fallback_keys:
        a = _clean(row.get(k) or "")
        if a:
            return a

    # 4) fallback to english if present
    for k in ("answer_en", "answer_english"):
        a = _clean(row.get(k) or "")
        if a:
            return a

    return ""


def find_library_answer(
    *,
    canonical_key: str,
    normalized_question: str = "",
    lang: str = "en",
) -> Optional[Dict[str, Any]]:
    """
    Returns:
      { "answer": "...", "lang_used": "<lang>", "canonical_key": "...", "source": "library", "id": <uuid?> }

    Strategy:
      1) Try exact canonical_key match in qa_library (preferred)
      2) If your schema doesn't have canonical_key, fallback to normalized_question match
         (kept best-effort so it won't crash)
    """
    canonical_key = _clean(canonical_key)
    normalized_question = _clean(normalized_question)
    lang = _norm_lang(lang)

    if not canonical_key and not normalized_question:
        return None

    # ---- Attempt A: canonical_key lookup ----
    try:
        res = (
            supabase()
            .table("qa_library")
            .select("*")
            .eq("canonical_key", canonical_key)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if rows:
            row = rows[0] or {}
            ans = _pick_answer_from_row(row, lang)
            if ans:
                return {
                    "id": row.get("id"),
                    "answer": ans,
                    "lang_used": lang,
                    "canonical_key": canonical_key,
                    "source": "library",
                }
    except Exception:
        # Column may not exist; ignore
        pass

    # ---- Attempt B: normalized question fallback ----
    if normalized_question:
        # Try common columns: normalized_question or question
        for col in ("normalized_question", "question"):
            try:
                res = (
                    supabase()
                    .table("qa_library")
                    .select("*")
                    .eq(col, normalized_question)
                    .limit(1)
                    .execute()
                )
                rows = getattr(res, "data", None) or []
                if rows:
                    row = rows[0] or {}
                    ans = _pick_answer_from_row(row, lang)
                    if ans:
                        return {
                            "id": row.get("id"),
                            "answer": ans,
                            "lang_used": lang,
                            "canonical_key": canonical_key or _clean(row.get("canonical_key") or ""),
                            "source": "library",
                        }
            except Exception:
                pass

    return None


# ------------------------------------------------------------
# Optional backward-compat aliases (in case other modules use
# different names)
# ------------------------------------------------------------
def get_library_answer(*args, **kwargs):
    return find_library_answer(*args, **kwargs)


def lookup_library_answer(*args, **kwargs):
    return find_library_answer(*args, **kwargs)
