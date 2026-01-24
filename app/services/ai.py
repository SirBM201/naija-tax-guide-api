import os
import logging
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def generate_answer(question: str, lang: str = "en") -> str:
    if not question:
        return ""

    try:
        prompt = f"""
You are a Nigerian tax assistant.
Answer clearly and professionally.

Question:
{question}
"""

        res = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": "You are a professional tax assistant."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=400,
        )

        return res.choices[0].message.content.strip()

    except Exception as e:
        logging.exception("AI generation failed: %s", e)
        return ""
