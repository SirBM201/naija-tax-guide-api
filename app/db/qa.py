# app/db/qa.py
from __future__ import annotations

import logging
from typing import Optional, Dict, Any

from supabase import create_client

from app.core.config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, RPC_MIN_SIM
from app.core.utils import normalize_question, now_utc, iso
from app.core.config import ANSWER_COLS


_sb = None


def _client():
    global _sb
    if _sb is not None:
        return _sb
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Supabase ENV not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).")
    _sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _sb


def pick_answer(row: Dict[str, Any], lang: str) -> Optional[str]:
    """
    Pick the best answer column based on lang, with fallbacks.
    """
    lang = (lang or "en").lower().strip()

    # Preferred order by language
    col_map = {
        "en": "answer_en",
        "pcm": "answer_pcm",
        "yo": "answer_yo",
        "ig": "answer_ig",
        "ha": "answer_ha",
    }

    preferred = col_map.get(lang)
    candidates = []

    if preferred:
        candidates.append(preferred)

    # fallbacks
    candidates += ["answer", "answer_en", "answer_pcm", "answer_yo", "answer_ig", "answer_ha"]

    for c in candidates:
        v = row.get(c)
        if isinstance(v, str) and v.strip():
            return v.strip()

    return None


def library_get(question: str, lang: str = "en") -> Optional[str]:
    """
    Find an answer from qa_library.
    Strategy:
      1) exact normalized match
      2) optional RPC fuzzy search (qa_library_search) if you created it
      3) fallback ilike search
    """
    q = (question or "").strip()
    if not q:
        return None

    sb = _client()
    nq = normalize_question(q)

    # 1) Exact normalized match
    try:
        r = (
            sb.table("qa_library")
            .select(f"{ANSWER_COLS},enabled,priority,normalized_question")
            .eq("enabled", True)
            .eq("normalized_question", nq)
            .order("priority", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        if rows:
            ans = pick_answer(rows[0], lang)
            if ans:
                return ans
    except Exception:
        logging.exception("qa_library exact lookup failed")

    # 2) RPC typo tolerant search (optional)
    try:
        # Your DB may have an RPC called qa_library_search(normalized_q text, min_sim float)
        r2 = sb.rpc("qa_library_search", {"normalized_q": nq, "min_sim": RPC_MIN_SIM}).execute()
        rows2 = getattr(r2, "data", None) or []
        if rows2:
            # Expecting row objects from qa_library
            best = rows2[0]
            ans2 = pick_answer(best, lang)
            if ans2:
                return ans2
    except Exception as e:
        # Non-fatal (you already log this in older code)
        logging.warning("Supabase RPC qa_library_search failed (non-fatal): %s", e)

    # 3) Fallback broad search
    try:
        r3 = (
            sb.table("qa_library")
            .select(f"{ANSWER_COLS},normalized_question,priority")
            .eq("enabled", True)
            .ilike("normalized_question", f"%{nq}%")
            .order("priority", desc=True)
            .limit(25)
            .execute()
        )
        rows3 = getattr(r3, "data", None) or []
        for row in rows3:
            ans3 = pick_answer(row, lang)
            if ans3:
                return ans3
    except Exception:
        logging.exception("qa_library ilike lookup failed")

    return None


def cache_get(question: str) -> Optional[str]:
    """
    Get cached answer from qa_cache, update last_used_at and use_count.
    """
    q = (question or "").strip()
    if not q:
        return None
    sb = _client()
    nq = normalize_question(q)

    try:
        r = (
            sb.table("qa_cache")
            .select("id,answer,use_count")
            .eq("normalized_question", nq)
            .order("last_used_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        if not rows:
            return None

        row = rows[0]
        ans = row.get("answer")
        if not isinstance(ans, str) or not ans.strip():
            return None

        # update usage (best effort)
        try:
            sb.table("qa_cache").update(
                {
                    "use_count": int(row.get("use_count") or 0) + 1,
                    "last_used_at": iso(now_utc()),
                }
            ).eq("id", row["id"]).execute()
        except Exception:
            logging.warning("qa_cache update failed (non-fatal)")

        return ans.strip()
    except Exception:
        logging.exception("qa_cache get failed")
        return None


def cache_set(question: str, answer: str) -> None:
    """
    Upsert cached answer into qa_cache.
    """
    q = (question or "").strip()
    a = (answer or "").strip()
    if not q or not a:
        return

    sb = _client()
    nq = normalize_question(q)

    try:
        sb.table("qa_cache").upsert(
            {
                "normalized_question": nq,
                "answer": a,
                "use_count": 0,
                "last_used_at": iso(now_utc()),
            },
            on_conflict="normalized_question",
        ).execute()
    except Exception:
        logging.exception("qa_cache set failed")
