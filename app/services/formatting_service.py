# app/services/formatting_service.py
from __future__ import annotations

def format_for_channel(text: str, channel: str) -> str:
    """
    Input text is stored in a neutral Markdown style.
    Convert to each channel format safely.
    """
    t = (text or "").strip()
    ch = (channel or "web").lower()

    if ch in ("web", "site"):
        return t  # markdown ok

    if ch in ("whatsapp", "telegram"):
        # WhatsApp/Telegram: markdown-lite is ok
        # Keep:
        # - bullets
        # - *bold*
        # - _italics_
        return t

    # default safe
    return t
