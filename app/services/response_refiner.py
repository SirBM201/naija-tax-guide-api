# app/services/response_refiner.py
from __future__ import annotations

from typing import Optional


_BAD_PATTERNS = [
    "ai temporarily unavailable",
    "ai service not configured",
    "openai_api_key not set",
    "invalid_api_key",
    "incorrect api key",
    "quota",
    "rate limit",
    "request timed out",
    "no answer generated",
    "openai import failed",
    "client init failed",
    "something went wrong",
]


def looks_like_ai_failure(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    for p in _BAD_PATTERNS:
        if p in t:
            return True
    return False


def refine_answer(raw: str, *, lang: str = "en", source: str = "ai") -> Optional[str]:
    """
    Return a clean answer or None if it's an AI failure / empty.
    Minimal changes (safe for production).
    """
    txt = (raw or "").strip()
    if not txt:
        return None

    if looks_like_ai_failure(txt):
        return None

    # Optional: small cleanup (no heavy formatting)
    # Remove repeated whitespace
    txt = "\n".join([line.rstrip() for line in txt.splitlines()]).strip()

    return txt or None
