# app/services/ai.py
from app.core.config import OPENAI_API_KEY, OPENAI_MODEL

def ai_answer_text(question: str, lang: str = "en") -> str:
    """
    Minimal safe AI stub.

    If you already have OpenAI wiring elsewhere, replace this with your real call.
    For now, it prevents crashes when module is imported.
    """
    q = (question or "").strip()
    if not OPENAI_API_KEY:
        return "AI is not configured yet (OPENAI_API_KEY missing). Please try again later."

    # Replace with your real OpenAI request logic.
    # Returning a deterministic placeholder prevents 500 errors.
    return f"(AI) I received your question: {q}. AI integration is enabled, but response generation is not wired yet."
