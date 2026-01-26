# message_router.py
from app.services.engine import answer_engine_reply


def route_message(sender_key: str, text: str) -> str:
    """
    Unified router for Telegram/WhatsApp/Web.
    Option 1: NO sessions, just respond using the engine.
    sender_key examples:
      - tg:123456789
      - wa:234xxxxxxxxxx
    """
    clean_text = (text or "").strip()
    if not clean_text:
        return "Please type your question."

    return answer_engine_reply(sender_key, clean_text)
