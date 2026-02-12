# app/services/response_refiner.py
from __future__ import annotations

import re
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
    "unauthorized",
    "401",
]

def looks_like_ai_failure(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    for p in _BAD_PATTERNS:
        if p in t:
            return True
    return False


def _cleanup_whitespace(txt: str) -> str:
    txt = (txt or "").strip()
    txt = "\n".join([line.rstrip() for line in txt.splitlines()])
    txt = re.sub(r"\n{3,}", "\n\n", txt).strip()
    return txt


def _ensure_sentence_case_first_line(txt: str) -> str:
    lines = txt.splitlines()
    if not lines:
        return txt
    first = lines[0].strip()
    if first and first[0].isalpha():
        first = first[0].upper() + first[1:]
    lines[0] = first
    return "\n".join(lines).strip()


def _web_markdown_polish(txt: str) -> str:
    # keep markdown, just clean spacing
    return _ensure_sentence_case_first_line(_cleanup_whitespace(txt))


def _wa_tg_polish(txt: str) -> str:
    """
    WhatsApp/Telegram-safe:
    - Avoid heavy markdown (**bold**) because WA uses *bold*
    - Keep bullets clean
    """
    txt = _cleanup_whitespace(txt)

    # Convert markdown bold **x** -> *x*
    txt = re.sub(r"\*\*(.+?)\*\*", r"*\1*", txt)

    # Convert headings like "Key points:" into WA-friendly emphasis
    txt = re.sub(r"(?m)^(key points|next steps|summary|important)\s*:\s*$", r"*\1:*", txt, flags=re.I)

    # Normalize bullets
    txt = re.sub(r"(?m)^\s*[-•]\s+", "- ", txt)

    return _ensure_sentence_case_first_line(txt)


def refine_answer(raw: str, *, lang: str = "en", source: str = "ai", provider: str = "web") -> Optional[str]:
    txt = (raw or "").strip()
    if not txt:
        return None
    if looks_like_ai_failure(txt):
        return None

    provider = (provider or "web").strip().lower()
    if provider in ("wa", "whatsapp", "tg", "telegram"):
        txt = _wa_tg_polish(txt)
    else:
        txt = _web_markdown_polish(txt)

    return txt or None
