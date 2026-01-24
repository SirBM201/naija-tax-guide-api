import os
import logging
from openai import OpenAI
from app.core.config import OPENAI_API_KEY, OPENAI_MODEL

client = OpenAI(api_key=OPENAI_API_KEY)

def generate_answer(question: str, lang: str = "en") -> str:
    try:
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a professional Nigerian tax advisor. "
                        "Give clear, structured, accurate answers."
                    ),
                },
                {
                    "role": "user",
                    "content": question,
                },
            ],
            temperature=0.3,
            timeout=12,  # <<< HARD STOP (IMPORTANT)
        )

        return resp.choices[0].message.content.strip()

    except Exception as e:
        logging.exception("OpenAI error: %s", e)
        return ""
