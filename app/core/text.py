# app/core/text.py
import re

_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s]", flags=re.UNICODE)

def normalize_question(q: str) -> str:
    """
    Normalizes question text so cache/library lookups are consistent.
    Example:
      "What is TIN??" -> "what is tin"
      "  VAT rate in Nigeria " -> "vat rate in nigeria"
    """
    s = (q or "").strip().lower()
    s = _PUNCT.sub(" ", s)          # remove punctuation
    s = _WS.sub(" ", s).strip()     # collapse whitespace
    return s
