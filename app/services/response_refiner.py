# app/services/response_refiner.py
from __future__ import annotations

import re
from typing import Optional


# ------------------------------------------------------------
# Heuristics for "bad" responses that should NOT be cached/sent
# ------------------------------------------------------------
_BAD_PATTERNS = [
    "ai temporarily unavailable",
    "ai service not configured",
    "openai_api_key not set",
    "openai api key not set",
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
    "openai is not connected",
]


def looks_like_ai_failure(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    for p in _BAD_PATTERNS:
        if p in t:
            return True
    return False


# ------------------------------------------------------------
# Cleanup helpers
# ------------------------------------------------------------
_RE_MULTI_BLANKS = re.compile(r"\n{3,}")
_RE_MULTI_SPACES = re.compile(r"[ \t]{2,}")
_RE_DISCLAIMER_LINES = re.compile(
    r"^(as an ai|i am an ai|i'm an ai|i cannot|i can't|i do not have access|"
    r"i don't have access|i am unable to|openai|chatgpt|model|api key).*$",
    re.IGNORECASE,
)


def _strip_junk_lines(txt: str) -> str:
    lines = []
    for line in (txt or "").splitlines():
        s = line.strip()
        if not s:
            lines.append("")
            continue
        # remove common disclaimers/noise
        if _RE_DISCLAIMER_LINES.match(s):
            continue
        lines.append(s)
    out = "\n".join(lines)
    out = _RE_MULTI_BLANKS.sub("\n\n", out)
    return out.strip()


def _normalize_whitespace(txt: str) -> str:
    txt = (txt or "").replace("\r\n", "\n").replace("\r", "\n")
    txt = "\n".join([_RE_MULTI_SPACES.sub(" ", ln).rstrip() for ln in txt.splitlines()])
    txt = _RE_MULTI_BLANKS.sub("\n\n", txt)
    return txt.strip()


def _make_whatsapp_friendly(txt: str) -> str:
    """
    Make message easy to read on chat UIs:
    - shorter paragraphs
    - bullets get spaced nicely
    """
    txt = (txt or "").strip()
    if not txt:
        return ""

    # Ensure bullets have a space after dash
    txt = re.sub(r"^\-\s*", "- ", txt, flags=re.MULTILINE)
    txt = re.sub(r"^\*\s*", "• ", txt, flags=re.MULTILINE)

    # If it’s one long paragraph, break into smaller chunks by sentences.
    if "\n" not in txt and len(txt) > 500:
        sentences = re.split(r"(?<=[.!?])\s+", txt)
        blocks = []
        cur = ""
        for s in sentences:
            if not s:
                continue
            if len(cur) + len(s) + 1 > 350:
                blocks.append(cur.strip())
                cur = s
            else:
                cur = (cur + " " + s).strip() if cur else s
        if cur:
            blocks.append(cur.strip())
        txt = "\n\n".join([b for b in blocks if b])

    return txt.strip()


# ------------------------------------------------------------
# Public API
# ------------------------------------------------------------
def refine_answer(raw: str, *, lang: str = "en", source: str = "ai") -> Optional[str]:
    """
    Returns a cleaned, user-ready message, or None if unusable.
    """
    txt = (raw or "").strip()
    if not txt:
        return None
    if looks_like_ai_failure(txt):
        return None

    txt = _strip_junk_lines(txt)
    txt = _normalize_whitespace(txt)

    if not txt or looks_like_ai_failure(txt):
        return None

    txt = _make_whatsapp_friendly(txt)

    # Final safety
    if not txt or looks_like_ai_failure(txt):
        return None

    return txt
