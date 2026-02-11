# app/services/response_refiner.py
from __future__ import annotations

from typing import Optional


_BAD_PATTERNS = [
    "ai temporarily unavailable",
    "ai service not configured",
    "openai_api_key not set",
    "invalid_api_key",
    "incorrect api key",
    "unauthorized",
    "401",
    "quota",
    "rate limit",
    "429",
    "request timed out",
    "timeout",
    "no answer generated",
    "openai import failed",
    "client init failed",
    "something went wrong",
    "request blocked",
]


def looks_like_ai_failure(text: str) -> bool:
    """
    Detects provider/system error text that must never be cached or shown as a real answer.
    """
    t = (text or "").strip().lower()
    if not t:
        return True
    for p in _BAD_PATTERNS:
        if p in t:
            return True
    return False


def _normalize_whitespace(txt: str) -> str:
    # trim trailing spaces per line, collapse excessive blank lines
    lines = [line.rstrip() for line in (txt or "").splitlines()]
    out: list[str] = []
    blank = 0
    for line in lines:
        if not line.strip():
            blank += 1
            if blank <= 1:
                out.append("")
            continue
        blank = 0
        out.append(line)
    return "\n".join(out).strip()


def refine_answer(raw: str, *, lang: str = "en", source: str = "ai") -> Optional[str]:
    """
    Returns refined text or None.
    - rejects AI/system failure strings
    - normalizes whitespace
    - keeps library/cached wording intact (light cleanup only)
    """
    txt = (raw or "").strip()
    if not txt:
        return None

    # For AI responses, reject failure-like output.
    if source in ("ai",):
        if looks_like_ai_failure(txt):
            return None

    # For all sources, normalize whitespace
    txt = _normalize_whitespace(txt)
    return txt or None
