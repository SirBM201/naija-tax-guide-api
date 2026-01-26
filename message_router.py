# message_router.py

from typing import Optional

# Your real engine is here (based on your folder structure screenshot)
from app.services.engine import answer_engine_reply


def route_message(sender_key: str, text: str) -> str:
    """
    sender_key examples:
      - wa:234xxxxxxxxxx
      - tg:123456789

    For now: no sessions, just respond using the AI/tax engine.
    We will re-add sessions after Telegram is stable.
    """
    clean_text = (text or "").strip()
    if not clean_text:
        return "Please type your question."

    return answer_engine_reply(sender_key, clean_text)
