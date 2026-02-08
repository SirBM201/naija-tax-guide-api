# app/services/ai_service.py

from __future__ import annotations

import os
from openai import OpenAI

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

client = OpenAI(api_key=OPENAI_API_KEY)


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
"""


def ask_ai(question: str, lang: str = "en") -> str:
    """
    Sends question to OpenAI and returns answer text.
    """

    if not OPENAI_API_KEY:
        return "AI service not configured."

    resp = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
        temperature=0.3,
    )

    return resp.choices[0].message.content
