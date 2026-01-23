# app/services/ai.py
from app.core.config import OPENAI_API_KEY, OPENAI_MODEL

def ai_answer_text(question: str, lang: str = "en") -> str:
    # Placeholder to keep your backend stable even before OpenAI wiring.
    # Next step: I can connect the OpenAI SDK to your existing API key.
    q = (question or "").strip()
    return f"(AI placeholder) You asked: {q}"
