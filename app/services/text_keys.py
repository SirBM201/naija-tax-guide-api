# app/services/text_keys.py
from __future__ import annotations
import re
from typing import Optional

_CURRENCY_RE = re.compile(r"(?i)\b(₦|ngn|\$|usd|eur|£)\s?\d[\d,]*(\.\d+)?\b")
_NUMBER_RE = re.compile(r"\b\d[\d,]*(\.\d+)?\b")
_WS_RE = re.compile(r"\s+")

def normalize_question(q: str) -> str:
    s = (q or "").strip().lower()
    s = s.replace("’", "'").replace("“", '"').replace("”", '"')
    s = _WS_RE.sub(" ", s)
    return s

def canonicalize_question(q: str, *, lang: str = "en") -> str:
    """
    Canonical key: cheap, deterministic, semantic-ish.
    Removes volatile parts: amounts, refs, dates-ish tokens, currencies.
    """
    s = normalize_question(q)

    # remove common ref markers
    s = re.sub(r"(?i)\bref\b[:\s]*[a-z0-9\-_/]+\b", " ", s)

    # remove currency+amount and raw numbers
    s = _CURRENCY_RE.sub(" ", s)
    s = _NUMBER_RE.sub(" ", s)

    # remove month names (optional cheap)
    s = re.sub(r"(?i)\b(jan|january|feb|february|mar|march|apr|april|may|jun|june|jul|july|aug|august|sep|sept|september|oct|october|nov|november|dec|december)\b", " ", s)

    # remove punctuation except apostrophes in words
    s = re.sub(r"[^\w\s']+", " ", s)
    s = _WS_RE.sub(" ", s).strip()

    # include lang to avoid cross-language collisions if desired
    # (but you already have (canonical_key, lang) unique in qa_cache)
    return s
