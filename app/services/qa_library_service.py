# app/services/qa_library_service.py
from __future__ import annotations

from typing import Any, Dict, Optional

from ..core.supabase_client import supabase


def find_library_answer(*, canonical_key: str, normalized_question: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    Priority:
      1) canonical_key + lang
      2) normalized_question + lang
    """
    db = supabase()
    canonical_key = (canonical_key or "").strip()
    normalized_question = (normalized_question or "").strip()
    lang = (lang or "en").strip().lower()

    # 1) canonical match
    if canonical_key:
        try:
            res = (
                db.table("qa_library")
                .select("id,answer,category,lang,normalized_question,canonical_key")
                .eq("canonical_key", canonical_key)
                .eq("lang", lang)
                .limit(1)
                .execute()
            )
            if res.data:
                row = res.data[0]
                ans = (row.get("answer") or "").strip()
                if ans:
                    return row
        except Exception:
            pass

    # 2) fallback normalized match
    if normalized_question:
        try:
            res = (
                db.table("qa_library")
                .select("id,answer,category,lang,normalized_question,canonical_key")
                .eq("normalized_question", normalized_question)
                .eq("lang", lang)
                .limit(1)
                .execute()
            )
            if res.data:
                row = res.data[0]
                ans = (row.get("answer") or "").strip()
                if ans:
                    return row
        except Exception:
            pass

    return None
