import os
import logging
from typing import Optional
import requests

# Read directly from environment (no config import -> no boot crash)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()

OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").strip()


def generate_answer(question: str, lang: str = "en") -> Optional[str]:
    """
    Returns answer text from OpenAI (or None if not configured / failed).
    Uses raw HTTPS requests (no 'openai' python package required).
    """

    if not OPENAI_API_KEY:
        logging.warning("AI disabled: OPENAI_API_KEY is not set")
        return None

    q = (question or "").strip()
    if not q:
        return None

    system = (
        "You are Naija Tax Guide. Give accurate Nigeria-focused tax guidance. "
        "Be clear and structured. Use short headings and bullets. "
        "If uncertain, say so and suggest checking FIRS or a tax professional."
    )

    # Minimal, stable payload for Chat Completions
    payload = {
        "model": OPENAI_MODEL,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": f"Language={lang}\n\nQuestion: {q}"},
        ],
    }

    try:
        r = requests.post(
            f"{OPENAI_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=25,
        )

        if r.status_code >= 400:
            logging.warning("OpenAI error %s: %s", r.status_code, r.text[:300])
            return None

        data = r.json()
        text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
            .strip()
        )
        return text or None

    except Exception as e:
        logging.exception("OpenAI request failed: %s", e)
        return None
