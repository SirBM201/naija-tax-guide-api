# app/services/ai.py
from app.core.config import OPENAI_API_KEY, OPENAI_MODEL

def ai_answer_text(question: str, lang: str = "en") -> str:
    # Safe placeholder to keep backend stable even before OpenAI wiring.
    # Next step: I will connect OpenAI SDK properly (and keep your caching rules intact).
    q = (question or "").strip()
    return f"(AI placeholder) You asked: {q}"
