# app/services/ai.py
from __future__ import annotations

from typing import Optional
import logging
import requests

from app.core.config import OPENAI_API_KEY, OPENAI_MODEL


def ai_answer_text(question: str, lang: str = "en") -> str:
    """
    Generate an answer using OpenAI via HTTP.
    Returns plain text.
    """
    q = (question or "").strip()
    if not q:
        return "Please ask a valid question."

    if not OPENAI_API_KEY:
        return "AI is temporarily unavailable (OPENAI_API_KEY not set). Please try again later."

    system = (
        "You are Naija Tax Guide, a helpful assistant focused on Nigerian taxation. "
        "Give accurate, practical, and concise guidance. "
        "If unsure, say what information is missing and recommend consulting FIRS/state IRS or a tax professional."
    )

    if (lang or "en").lower() != "en":
        system += f" Respond in language='{lang}'. Keep it clear and simple."

    payload = {
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": q},
        ],
        "temperature": 0.2,
    }

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=45,
        )
        if resp.status_code >= 400:
            logging.warning("OpenAI error %s: %s", resp.status_code, resp.text[:500])
            return "AI is temporarily unavailable. Please try again shortly."

        data = resp.json()
        text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        text = (text or "").strip()
        return text or "I could not generate an answer. Please try again."
    except Exception:
        logging.exception("OpenAI request failed")
        return "AI is temporarily unavailable. Please try again later."
