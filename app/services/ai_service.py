# app/services/ai_service.py
from __future__ import annotations

import os
from typing import Optional

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
_last_error: Optional[str] = None
_openai_import_error: Optional[str] = None


def _set_last_error(msg: str) -> None:
    global _last_error
    _last_error = (msg or "").strip()[:4000] or None


def get_last_ai_error() -> Optional[str]:
    return _last_error


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()


def _get_client():
    """
    Singleton OpenAI client.
    Reads OPENAI_API_KEY at runtime so Koyeb env var changes work without code changes.
    """
    global _ai_client, _openai_import_error

    if _ai_client is not None:
        return _ai_client

    api_key = _env("OPENAI_API_KEY")
    if not api_key:
        _openai_import_error = "OPENAI_API_KEY not set"
        _set_last_error(_openai_import_error)
        return None

    try:
        from openai import OpenAI
    except Exception as e:
        _openai_import_error = "openai import failed"
        _set_last_error(f"openai import failed: {type(e).__name__}")
        return None

    try:
        _ai_client = OpenAI(api_key=api_key)
        return _ai_client
    except Exception as e:
        _openai_import_error = "OpenAI client init failed"
        _set_last_error(f"OpenAI client init failed: {type(e).__name__}")
        return None


def ask_ai(question: str, lang: str = "en") -> Optional[str]:
    """
    Returns:
      - answer text (str) on success
      - None on failure (so ask_service can refund credits + NOT cache)
    """
    q = (question or "").strip()
    if not q:
        _set_last_error("empty question")
        return None

    client = _get_client()
    if client is None:
        return None

    model = _env("OPENAI_MODEL", "gpt-4.1-mini")

    try:
        user_msg = f"[Language: {lang}] {q}" if lang else q

        resp = client.responses.create(
            model=model,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            temperature=0.3,
        )

        out = getattr(resp, "output", None)
        if not out:
            _set_last_error("No output from model")
            return None

        for item in out:
            if getattr(item, "type", None) == "message":
                for c in (getattr(item, "content", None) or []):
                    if getattr(c, "type", None) == "output_text":
                        text = (getattr(c, "text", "") or "").strip()
                        if text:
                            _set_last_error("")
                            return text

        _set_last_error("No output_text content found")
        return None

    except Exception as e:
        msg = str(e).lower()

        if "401" in msg or "unauthorized" in msg or "invalid_api_key" in msg:
            _set_last_error("OpenAI 401 Unauthorized (check OPENAI_API_KEY in Koyeb env vars)")
            return None

        if "429" in msg or "rate limit" in msg or "quota" in msg:
            _set_last_error("OpenAI rate/quota limit reached (429). Try again later.")
            return None

        if "timeout" in msg:
            _set_last_error("OpenAI request timed out. Try again.")
            return None

        _set_last_error(f"OpenAI request failed: {type(e).__name__}")
        return None
