# app/services/ai_service.py

from __future__ import annotations

import os
from typing import Optional, Tuple

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()

SYSTEM_PROMPT = """
You are Naija Tax AI — a professional Nigerian tax assistant.

You help with:
- FIRS tax rules
- Freelancer tax
- Business registration
- VAT
- PAYE
- Record keeping
- Compliance

Be concise, accurate, and practical.
""".strip()

_ai_client = None
_openai_import_error: Optional[str] = None
_last_error: Optional[str] = None


def _set_last_error(msg: str) -> None:
    global _last_error
    _last_error = (msg or "").strip()[:4000] or None


def get_last_ai_error() -> Optional[str]:
    return _last_error


def _get_client():
    global _ai_client, _openai_import_error

    if _ai_client is not None:
        return _ai_client

    if not OPENAI_API_KEY:
        _openai_import_error = "OPENAI_API_KEY not set"
        _set_last_error(_openai_import_error)
        return None

    try:
        from openai import OpenAI
    except Exception as e:
        _openai_import_error = f"openai import failed: {e}"
        _set_last_error(_openai_import_error)
        return None

    try:
        _ai_client = OpenAI(api_key=OPENAI_API_KEY)
        return _ai_client
    except Exception as e:
        _openai_import_error = f"OpenAI client init failed: {e}"
        _set_last_error(_openai_import_error)
        return None


def ask_ai(question: str, lang: str = "en") -> Optional[str]:
    """
    Returns:
      - answer text (str) on success
      - None on failure (so ask_service can refund credits + NOT cache)
    """
    q = (question or "").strip()
    if not q:
        return None

    client = _get_client()
    if client is None:
        _set_last_error("AI not configured")
        return None

    try:
        user_msg = f"[Language: {lang}] {q}" if lang else q

        resp = client.responses.create(
            model=OPENAI_MODEL,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.3,
        )

        if not getattr(resp, "output", None):
            _set_last_error("No output from model")
            return None

        for item in resp.output:
            if getattr(item, "type", None) == "message":
                for c in (item.content or []):
                    if getattr(c, "type", None) == "output_text":
                        text = (c.text or "").strip()
                        if text:
                            _set_last_error("")
                            return text

        _set_last_error("No output_text content found")
        return None

    except Exception as e:
        # IMPORTANT: do not return raw exception text to users and do not allow it into cache
        _set_last_error(str(e))
        return None
