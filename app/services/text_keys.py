# app/services/text_keys.py
from __future__ import annotations
import re
import unicodedata
from typing import Optional

_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s₦$€£]", flags=re.UNICODE)

# Very conservative amount normalizer:
# - Converts "₦100,000" / "$10,000" to "<money>"
# - Only when a currency symbol is present (prevents breaking normal numbers like "2025")
_MONEY = re.compile(r"(₦|\$|€|£)\s*\d[\d,]*(\.\d+)?", flags=re.IGNORECASE)

def _nfkc(s: str) -> str:
    return unicodedata.normalize("NFKC", s)

def canonicalize_question(q: str, *, lang: Optional[str] = None) -> str:
    """
    Produces a stable canonical key for meaning-equivalent questions.

    IMPORTANT:
    - Does NOT translate (keeps cost low).
    - Does NOT aggressively stem (reduces wrong matches).
    """
    s = (q or "").strip()
    s = _nfkc(s)
    s = s.lower()

    # money normalization (safe only when currency symbol exists)
    s = _MONEY.sub("<money>", s)

    # remove punctuation noise but keep words/numbers/underscore
    s = _PUNCT.sub(" ", s)

    # collapse whitespace
    s = _WS.sub(" ", s).strip()

    # optional: tag language to reduce cross-language collisions
    # (keeps your UNIQUE(canonical_key, lang) strong)
    if lang:
        s = f"{lang}:{s}"

    return s
