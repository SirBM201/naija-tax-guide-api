from __future__ import annotations

"""
QA CACHE SERVICE (BOOT-SAFE + SMARTER MATCHING)

Exports:
  - find_cached_answer(...)
  - touch_cache_best_effort(...)
  - upsert_ai_answer_to_cache_best_effort(...)
  - answer_from_cache(...)
  - increment_cache_use(...)
  - normalize_question_for_cache(...)
  - derive_canonical_key(...)

Strategy:
  1. exact canonical_key + lang
  2. exact normalized_question + lang
  3. fallback canonical_key without lang
"""

from typing import Optional, Dict, Any
from datetime import datetime, timezone
import re

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clean_text(q: str) -> str:
    q = (q or "").strip().lower()
    q = re.sub(r"[^\w\s]", " ", q)
    q = re.sub(r"\s+", " ", q).strip()
    return q


def _drop_filler_words(q: str) -> str:
    fillers = {
        "please", "pls", "abeg", "kindly", "help", "explain", "tell", "me",
        "can", "could", "you", "do", "i", "need", "to", "for", "about",
        "the", "a", "an", "is", "are", "be", "what", "whats", "meaning",
        "of", "na", "wetin", "which", "where", "when"
    }
    parts = [p for p in q.split() if p not in fillers]
    return " ".join(parts).strip()


def normalize_question_for_cache(q: str) -> str:
    """
    Stronger normalization than before:
    - lowercase
    - remove punctuation
    - compress spaces
    - remove filler words
    - normalize common variants / typos
    """
    q = _clean_text(q)

    replacements = {
        r"\bmeaing\b": "meaning",
        r"\bmeaning\b": "meaning",
        r"\bwetin\b": "what",
        r"\bdey\b": "is",
        r"\bvat\b": "vat",
        r"\bpaye\b": "paye",
        r"\btaxable income\b": "taxable_income",
        r"\bpersonal income tax\b": "personal_income_tax",
        r"\bpay as you earn\b": "paye",
        r"\bstate inland revenue service\b": "sirs",
        r"\bfederal inland revenue service\b": "firs",
    }

    for pattern, repl in replacements.items():
        q = re.sub(pattern, repl, q)

    q = _drop_filler_words(q)
    q = re.sub(r"\s+", " ", q).strip()
    return q


def derive_canonical_key(question: str, lang: str = "en") -> Optional[str]:
    """
    Maps variant phrasings to shared intent keys.
    Keep this conservative to avoid wrong matches.
    """
    q = normalize_question_for_cache(question)
    lang = (lang or "en").strip().lower() or "en"

    rules = [
        ("taxable_income_meaning", [
            "taxable_income",
            "meaning taxable_income",
            "taxable_income meaning",
            "taxable_income explain",
        ]),
        ("what_is_vat", [
            "vat",
            "meaning vat",
            "what vat",
        ]),
        ("what_is_paye", [
            "paye",
            "what paye",
            "meaning paye",
        ]),
        ("can_i_negotiate_vat", [
            "negotiate vat",
            "can negotiate vat",
        ]),
        ("how_to_file_vat_returns", [
            "file vat returns",
            "how file vat returns",
            "when file vat returns",
        ]),
        ("where_to_pay_personal_income_tax", [
            "pay personal_income_tax",
            "where pay tax",
            "state sirs or firs",
            "pay tax state inland revenue service",
        ]),
    ]

    for key, patterns in rules:
        for p in patterns:
            if p in q:
                return key

    return None


def find_cached_answer(
    normalized_question: str,
    lang: str = "en",
    canonical_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    nq = (normalized_question or "").strip()
    if not nq and not canonical_key:
        return None

    lang = (lang or "en").strip() or "en"

    try:
        # 1. exact canonical key + lang
        if canonical_key and canonical_key.strip():
            ck = canonical_key.strip()
            res = (
                _sb().table("qa_cache")
                .select("*")
                .eq("enabled", True)
                .eq("canonical_key", ck)
                .eq("lang", lang)
                .order("priority", desc=True)
                .limit(1)
                .execute()
            )
            if getattr(res, "data", None):
                return res.data[0]

        # 2. exact normalized question + lang
        if nq:
            res = (
                _sb().table("qa_cache")
                .select("*")
                .eq("enabled", True)
                .eq("normalized_question", nq)
                .eq("lang", lang)
                .order("priority", desc=True)
                .limit(1)
                .execute()
            )
            if getattr(res, "data", None):
                return res.data[0]

        # 3. fallback canonical key without lang
        if canonical_key and canonical_key.strip():
            ck = canonical_key.strip()
            res = (
                _sb().table("qa_cache")
                .select("*")
                .eq("enabled", True)
                .eq("canonical_key", ck)
                .order("priority", desc=True)
                .limit(1)
                .execute()
            )
            if getattr(res, "data", None):
                return res.data[0]

        return None
    except Exception:
        return None


def touch_cache_best_effort(cache_id: str) -> None:
    cid = (cache_id or "").strip()
    if not cid:
        return
    try:
        res = _sb().table("qa_cache").select("use_count").eq("id", cid).limit(1).execute()
        current = 0
        if getattr(res, "data", None):
            current = int(res.data[0].get("use_count") or 0)

        _sb().table("qa_cache").update(
            {"use_count": current + 1, "last_used_at": _now_iso()}
        ).eq("id", cid).execute()
    except Exception:
        return


def upsert_ai_answer_to_cache_best_effort(
    normalized_question: str,
    answer: str,
    tags: Optional[Any] = None,
    source: str = "ai",
    lang: str = "en",
    canonical_key: Optional[str] = None,
    enabled: bool = True,
    priority: int = 0,
) -> None:
    raw_q = (normalized_question or "").strip()
    ans = (answer or "").strip()
    if not raw_q or not ans:
        return

    lang = (lang or "en").strip() or "en"
    nq = normalize_question_for_cache(raw_q)
    ck = canonical_key.strip() if canonical_key and canonical_key.strip() else derive_canonical_key(raw_q, lang=lang)

    payload: Dict[str, Any] = {
        "normalized_question": nq,
        "answer": ans,
        "tags": tags if tags is not None else [],
        "source": source,
        "enabled": bool(enabled),
        "priority": int(priority or 0),
        "lang": lang,
        "last_used_at": _now_iso(),
    }

    if ck:
        payload["canonical_key"] = ck

    try:
        if payload.get("canonical_key"):
            _sb().table("qa_cache").upsert(
                payload,
                on_conflict="canonical_key,lang"
            ).execute()
        else:
            _sb().table("qa_cache").upsert(
                payload,
                on_conflict="normalized_question,lang"
            ).execute()
    except Exception:
        return


def answer_from_cache(question: str, lang: str = "en", canonical_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    nq = normalize_question_for_cache(question)
    ck = canonical_key.strip() if canonical_key and canonical_key.strip() else derive_canonical_key(question, lang=lang)
    return find_cached_answer(nq, lang=lang, canonical_key=ck)


def increment_cache_use(cache_id: Optional[str]) -> None:
    if not cache_id:
        return
    touch_cache_best_effort(cache_id)
