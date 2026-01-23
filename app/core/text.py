# app/core/text.py
import re

_WS = re.compile(r"\s+")
_NON_WORD = re.compile(r"[^\w\s]+", flags=re.UNICODE)

def normalize_question(q: str) -> str:
    """
    Normalizes user questions into a stable key for matching/caching.
    - lowercase
    - remove punctuation
    - collapse whitespace
    """
    s = (q or "").strip().lower()
    s = _NON_WORD.sub(" ", s)     # remove punctuation/symbols
    s = _WS.sub(" ", s).strip()   # collapse spaces
    return s
