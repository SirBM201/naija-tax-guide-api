import logging
from typing import Any, Dict, Optional, List


def _db():
    from app.db.supabase_client import supabase as get_supabase
    return get_supabase()


def _answer_columns_for_lang(lang: str) -> List[str]:
    l = (lang or "en").lower().strip()

    if l in ("en", "english"):
        return ["answer_en"]

    if l in ("pcm", "pidgin"):
        return ["answer_pcm", "answer_pidgin"]

    if l in ("yo", "yoruba"):
        return ["answer_yo", "answer_yoruba"]

    if l in ("ig", "igbo"):
        return ["answer_ig", "answer_igbo"]

    if l in ("ha", "hausa"):
        return ["answer_ha", "answer_hausa"]

    return ["answer_en"]


# -----------------------------
# Cache
# -----------------------------
def cache_get(normalized_question: str, lang: str = "en") -> Optional[Dict[str, Any]]:
    """
    Reads from qa_cache. We assume qa_cache stores one answer per normalized_question+lang
    OR at least stores one answer per normalized_question.
    This is best-effort: if lang column doesn't exist, it falls back.
    """
    q = (normalized_question or "").strip()
    if not q:
        return None

    try:
        # First try: normalized_question + lang
        res = (
            _db()
            .table("qa_cache")
            .select("*")
            .eq("normalized_question", q)
            .eq("lang", (lang or "en"))
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if rows:
            row = rows[0]
            ans = row.get("answer") or row.get("answer_text")
            if ans:
                return {"answer": ans, "row": row}

    except Exception as e:
        logging.exception("qa_cache get (lang) failed, will retry without lang: %s", e)

    # Retry without lang constraint (in case qa_cache doesn't store lang)
    try:
        res = (
            _db()
            .table("qa_cache")
            .select("*")
            .eq("normalized_question", q)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if rows:
            row = rows[0]
            ans = row.get("answer") or row.get("answer_text")
            if ans:
                return {"answer": ans, "row": row}
    except Exception as e2:
        logging.exception("qa_cache get failed: %s", e2)

    return None


def cache_put(normalized_question: str, answer: str, lang: str = "en", tags=None, source: str = "web") -> None:
    """
    Best-effort cache write.
    Uses upsert when possible. If cache schema differs, errors are ignored.
    """
    q = (normalized_question or "").strip()
    a = (answer or "").strip()
    if not q or not a:
        return

    payload = {
        "normalized_question": q,
        "answer": a[:4000],
        "source": source,
        "tags": tags or [],
        "lang": (lang or "en"),
    }

    try:
        # Try upsert with normalized_question+lang conflict (if exists)
        _db().table("qa_cache").upsert(payload, on_conflict="normalized_question,lang").execute()
        return
    except Exception:
        pass

    try:
        # Try upsert with normalized_question only (if that's your unique key)
        _db().table("qa_cache").upsert(payload, on_conflict="normalized_question").execute()
        return
    except Exception:
        pass

    try:
        # Fallback insert
        _db().table("qa_cache").insert(payload).execute()
    except Exception as e:
        logging.exception("qa_cache put failed (ignored): %s", e)


# -----------------------------
# Library
# -----------------------------
def library_get(normalized_question: str, lang: str = "en") -> Optional[Dict[str, Any]]:
    """
    Reads from qa_library:
      - finds row by normalized_question
      - returns the right answer column based on lang
    """
    q = (normalized_question or "").strip()
    if not q:
        return None

    try:
        res = (
            _db()
            .table("qa_library")
            .select("*")
            .eq("normalized_question", q)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return None

        row = rows[0]
        # pick the first non-null answer col for this lang
        for col in _answer_columns_for_lang(lang):
            val = row.get(col)
            if val:
                return {"answer": val, "row": row}

        # fallback to English if requested lang missing
        if row.get("answer_en"):
            return {"answer": row.get("answer_en"), "row": row}

        return None

    except Exception as e:
        logging.exception("qa_library get failed: %s", e)
        return None
