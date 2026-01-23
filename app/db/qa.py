# app/db/qa.py
from typing import Optional
from app.core.config import ENABLE_QA_LIBRARY, ENABLE_QA_CACHE, SYNONYMS
from app.core.utils import normalize_question
from app.db.supabase_rest import sb_get, sb_patch, sb_post


def _pick_lang_answer(row: dict, lang: str) -> str:
    lang = (lang or "en").lower()
    # Map language to column name
    col = {
        "en": "answer_en",
        "pcm": "answer_pcm",
        "yo": "answer_yo",
        "ig": "answer_ig",
        "ha": "answer_ha",
    }.get(lang, "answer_en")

    # Prefer lang column, then generic answer, then English
    return (row.get(col) or row.get("answer") or row.get("answer_en") or "").strip()


def library_get(question: str, lang: str = "en") -> Optional[str]:
    if not ENABLE_QA_LIBRARY:
        return None

    nq = normalize_question(question)

    # 1) Exact match
    rows = sb_get(
        "qa_library",
        params={
            "select": "answer,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha,enabled,priority,normalized_question",
            "normalized_question": f"eq.{nq}",
            "enabled": "eq.True",
            "order": "priority.desc",
            "limit": "1",
        },
    )
    if rows:
        return _pick_lang_answer(rows[0], lang) or None

    # 2) Synonym expansion (simple)
    for key, variants in SYNONYMS.items():
        if key in nq:
            for v in variants:
                rows2 = sb_get(
                    "qa_library",
                    params={
                        "select": "answer,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha,enabled,priority,normalized_question",
                        "normalized_question": f"eq.{normalize_question(v)}",
                        "enabled": "eq.True",
                        "order": "priority.desc",
                        "limit": "1",
                    },
                )
                if rows2:
                    return _pick_lang_answer(rows2[0], lang) or None

    # 3) ILIKE fallback
    rows3 = sb_get(
        "qa_library",
        params={
            "select": "answer,answer_en,answer_pcm,answer_yo,answer_ig,answer_ha,enabled,priority,normalized_question",
            "enabled": "eq.True",
            "normalized_question": f"ilike.%{nq[:20]}%",
            "order": "priority.desc",
            "limit": "1",
        },
    )
    if rows3:
        return _pick_lang_answer(rows3[0], lang) or None

    return None


def cache_get(question: str) -> Optional[str]:
    if not ENABLE_QA_CACHE:
        return None

    nq = normalize_question(question)
    rows = sb_get(
        "qa_cache",
        params={
            "select": "id,answer,use_count,last_used_at",
            "normalized_question": f"eq.{nq}",
            "order": "last_used_at.desc",
            "limit": "1",
        },
    )
    if not rows:
        return None

    row = rows[0]
    # best effort: increment use_count
    try:
        use_count = int(row.get("use_count") or 0) + 1
        sb_patch("qa_cache", {"use_count": use_count}, params={"id": f"eq.{row.get('id')}"})
    except Exception:
        pass

    return (row.get("answer") or "").strip() or None


def cache_set(question: str, answer: str) -> None:
    if not ENABLE_QA_CACHE:
        return
    nq = normalize_question(question)

    # Try insert; if conflict exists, just insert another row is OK,
    # or you can enforce uniqueness at DB later.
    sb_post("qa_cache", {"normalized_question": nq, "answer": answer, "use_count": 0})
