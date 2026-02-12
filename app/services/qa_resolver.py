# app/services/qa_resolver.py
from __future__ import annotations

import re
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone

from ..core.supabase_client import supabase


# -----------------------------
# Helpers
# -----------------------------
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_question(q: str) -> str:
    """
    Your lightweight normalizer.
    - lower
    - remove extra spaces
    - remove currency/amount refs like "₦50,000", "$10,000", "ref 250k"
    - keep meaning words
    """
    q = (q or "").strip().lower()
    q = re.sub(r"\s+", " ", q)

    # remove common "ref ..." patterns
    q = re.sub(r"\(.*?ref.*?\)", "", q)
    q = re.sub(r"\bref\b[:\s]*[^\s]+\b", "", q)

    # remove currency amounts (₦, $, NGN, USD) with digits/commas/k
    q = re.sub(r"(₦|\$)\s?\d[\d,\.]*(k|m)?", "", q)
    q = re.sub(r"\b(ngn|usd|naira|dollars?)\b\s?\d[\d,\.]*(k|m)?", "", q)

    q = re.sub(r"\s+", " ", q).strip()
    return q


def canonical_key(q_normalized: str) -> str:
    """
    Canonical key: stable, deterministic.
    This is NOT “semantic AI”. It’s rule-based normalization -> good enough for many repeats.
    You can improve later without breaking DB, because canonical_key is stored.
    """
    q = (q_normalized or "").strip().lower()
    q = re.sub(r"[^a-z0-9\s]", "", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q


def _lang_to_library_col(lang: str) -> str:
    """
    Map incoming lang to qa_library columns you already have.
    Adjust names here if your exact column names differ.
    """
    l = (lang or "en").strip().lower()
    # accept multiple aliases
    if l in ("en", "eng", "english"):
        return "answer_en"
    if l in ("yo", "yor", "yoruba"):
        return "answer_yoruba"
    if l in ("ig", "ibo", "igbo"):
        return "answer_igbo"
    if l in ("ha", "hau", "hausa"):
        return "answer_hausa"
    if l in ("pcm", "pidgin", "pigin"):
        # choose whichever you actually use (you showed both styles earlier)
        # if you keep BOTH columns, prefer answer_pidgin first, else answer_pcmd.
        return "answer_pidgin"
    return "answer_en"


# -----------------------------
# DB lookups
# -----------------------------
def _lookup_library(ckey: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    Returns dict: {answer, lang_used, source='library', id, canonical_key}
    Fallback: if requested lang answer null -> use English.
    """
    db = supabase()
    want_col = _lang_to_library_col(lang)

    # Select the requested column + English fallback
    res = (
        db.table("qa_library")
        .select(f"id, canonical_key, enabled, {want_col}, answer_en")
        .eq("canonical_key", ckey)
        .eq("enabled", True)
        .limit(1)
        .execute()
    )
    if not res.data:
        return None

    row = res.data[0]
    ans = (row.get(want_col) or "").strip()
    if ans:
        return {"answer": ans, "lang_used": lang, "source": "library", "id": row.get("id"), "canonical_key": ckey}

    # fallback to English
    ans_en = (row.get("answer_en") or "").strip()
    if ans_en:
        return {"answer": ans_en, "lang_used": "en", "source": "library", "id": row.get("id"), "canonical_key": ckey}

    return None


def _lookup_cache(ckey: str, lang: str) -> Optional[Dict[str, Any]]:
    """
    qa_cache is AI-only storage.
    We search by canonical_key + lang, then fallback to canonical_key + en.
    """
    db = supabase()
    l = (lang or "en").strip().lower()

    def _fetch(target_lang: str) -> Optional[Dict[str, Any]]:
        r = (
            db.table("qa_cache")
            .select("id, canonical_key, answer, lang, enabled")
            .eq("canonical_key", ckey)
            .eq("enabled", True)
            .eq("lang", target_lang)
            .order("priority", desc=True)
            .order("last_used_at", desc=True)
            .limit(1)
            .execute()
        )
        if not r.data:
            return None
        row = r.data[0]
        ans = (row.get("answer") or "").strip()
        if not ans:
            return None

        # best-effort usage ping
        try:
            db.table("qa_cache").update({"last_used_at": _now_iso()}).eq("id", row["id"]).execute()
        except Exception:
            pass

        return {"answer": ans, "lang_used": row.get("lang") or target_lang, "source": "cache", "id": row.get("id"), "canonical_key": ckey}

    hit = _fetch(l)
    if hit:
        return hit
    if l != "en":
        return _fetch("en")
    return None


def save_ai_to_cache(*, ckey: str, normalized_q: str, answer: str, lang: str) -> None:
    """
    Save ONLY AI answers to cache. (Your rule)
    Store normalized_question + answer + canonical_key + lang.
    """
    db = supabase()
    row = {
        "canonical_key": ckey,
        "normalized_question": normalized_q,
        "answer": answer,
        "lang": (lang or "en").strip().lower(),
        "enabled": True,
        "priority": 50,
        "created_at": _now_iso(),
        "last_used_at": _now_iso(),
        "source": "ai",
    }
    try:
        db.table("qa_cache").insert(row).execute()
    except Exception:
        # If you later add a UNIQUE constraint, switch to upsert here.
        pass


# -----------------------------
# Public resolver API
# -----------------------------
def resolve_qa(*, question: str, lang: str = "en") -> Dict[str, Any]:
    """
    Does NOT call AI.
    Returns:
      { ok, hit, source, answer, canonical_key, normalized_question, lang_used }
    """
    nq = normalize_question(question)
    ckey = canonical_key(nq)

    lib = _lookup_library(ckey, lang)
    if lib:
        return {
            "ok": True,
            "hit": True,
            "source": lib["source"],
            "answer": lib["answer"],
            "canonical_key": ckey,
            "normalized_question": nq,
            "lang_used": lib["lang_used"],
        }

    cache = _lookup_cache(ckey, lang)
    if cache:
        return {
            "ok": True,
            "hit": True,
            "source": cache["source"],
            "answer": cache["answer"],
            "canonical_key": ckey,
            "normalized_question": nq,
            "lang_used": cache["lang_used"],
        }

    return {
        "ok": True,
        "hit": False,
        "source": "miss",
        "answer": None,
        "canonical_key": ckey,
        "normalized_question": nq,
        "lang_used": (lang or "en").strip().lower(),
    }
