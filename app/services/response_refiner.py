# app/services/response_refiner.py

from __future__ import annotations

import os
import re
from typing import Optional

# ------------------------------------------------------------
# Refinement / Formatting (shared across cache + AI + all channels)
# ------------------------------------------------------------
REFINE_ENABLED = (os.getenv("REFINE_ENABLED", "1") or "1").strip() in ("1", "true", "yes", "on")
ADD_DISCLAIMER = (os.getenv("ADD_TAX_DISCLAIMER", "1") or "1").strip() in ("1", "true", "yes", "on")
MAX_LEN = int((os.getenv("ANSWER_MAX_CHARS", "6000") or "6000").strip())


_ERROR_PATTERNS = [
    r"\binvalid_api_key\b",
    r"\bincorrect api key\b",
    r"\bopenai\b.*\bapi key\b",
    r"\b401\b",
    r"\b403\b",
    r"\b429\b",
    r"\bai temporarily unavailable\b",
    r"\bservice not configured\b",
    r"\btraceback\b",
    r"\bexception\b",
    r"\berror code\b",
]


def looks_like_error_answer(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    # Too short & looks like a system failure
    if len(t) < 8 and any(x in t for x in ("error", "failed", "unavailable")):
        return True
    for p in _ERROR_PATTERNS:
        if re.search(p, t, flags=re.IGNORECASE):
            return True
    return False


def _basic_cleanup(text: str) -> str:
    t = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    # remove very long repeated stars/lines that break UI
    t = re.sub(r"\*{20,}", "", t)
    t = re.sub(r"-{20,}", "", t)
    # collapse crazy whitespace
    t = re.sub(r"\n{4,}", "\n\n", t)
    t = re.sub(r"[ \t]{3,}", "  ", t)
    return t.strip()


def _append_disclaimer(text: str, lang: str) -> str:
    # Keep disclaimer English-only for now (simple + safe)
    l = (lang or "en").strip().lower()
    if l not in ("en", "pcm"):
        return text
    return (
        text
        + "\n\n---\n"
        + "_Note: This is general tax guidance. For official confirmation, check FIRS rules or consult a licensed tax professional._"
    )


def refine_answer(answer: str, *, lang: str = "en", source: str = "") -> Optional[str]:
    """
    Returns refined answer text, or None if the answer should be treated as invalid.
    Applied to BOTH cache answers and AI answers.
    """
    if not REFINE_ENABLED:
        # still block obvious error answers
        if looks_like_error_answer(answer):
            return None
        return (answer or "").strip()[:MAX_LEN] or None

    cleaned = _basic_cleanup(answer)

    # Block any "error-like" answers so they never get cached or returned as normal.
    if looks_like_error_answer(cleaned):
        return None

    # Enforce max length (avoid UI explosion)
    if len(cleaned) > MAX_LEN:
        cleaned = cleaned[:MAX_LEN].rstrip() + "…"

    # Optional disclaimer
    if ADD_DISCLAIMER:
        cleaned = _append_disclaimer(cleaned, lang)

    return cleaned or None
