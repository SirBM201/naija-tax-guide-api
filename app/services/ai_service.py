# app/services/ai_service.py

from __future__ import annotations

import os
from typing import Optional

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

# Lazy client cache
_ai_client = None
_openai_import_error: Optional[str] = None


# -------------------------------------------------
# Lazy OpenAI client loader
# -------------------------------------------------
def _get_client():
    global _ai_client, _openai_import_error

    if _ai_client is not None:
        return _ai_client

    if not OPENAI_API_KEY:
        _openai_import_error = "OPENAI_API_KEY not set"
        return None

    try:
        from openai import OpenAI  # v1 SDK
    except Exception as e:
        _openai_import_error = f"openai import failed: {e}"
        return None

    try:
        _ai_client = OpenAI(api_key=OPENAI_API_KEY)
        return _ai_client
    except Exception as e:
        _openai_import_error = f"OpenAI client init failed: {e}"
        return None


# -------------------------------------------------
# AI Ask Function
# -------------------------------------------------
def ask_ai(question: str, lang: str = "en") -> str:
    """
    Sends question to OpenAI and returns answer text.
    Safe fallback if AI not configured.
    """

    q = (question or "").strip()
    if not q:
        return "Please provide a question."

    client = _get_client()
    if client is None:
        return "AI service not configured yet. Please contact support or try again later."

    try:
        user_msg = f"[Language: {lang}] {q}" if lang else q

        resp = client.responses.create(
            model=OPENAI_MODEL,
            input=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT,
                },
                {
                    "role": "user",
                    "content": user_msg,
                },
            ],
            temperature=0.3,
        )

        # Extract text safely
        if not resp.output:
            return "No answer generated."

        # responses API returns structured output
        for item in resp.output:
            if item.type == "message":
                for c in item.content:
                    if c.type == "output_text":
                        return c.text

        return "No answer generated."

    except Exception as e:
        return f"AI temporarily unavailable. ({str(e)})"
