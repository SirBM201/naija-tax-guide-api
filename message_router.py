# message_router.py (repo root)
from typing import Optional

from app.services.engine import resolve_answer


def route_message(identity: str, text: str, lang: str = "en") -> str:
    """
    Central router for Telegram/WhatsApp/Web.

    For now:
      - Route everything to the AI/cache/library engine.
    Later:
      - You can re-introduce sessions/flows when session_service exists.
    """
    clean_text = (text or "").strip()
    if not clean_text:
        return "Please type your question."

    result = resolve_answer(
        wa_phone=(identity or "").strip(),
        question=clean_text,
        lang=lang,
        source="telegram",
    )

    if result.get("ok"):
        return (result.get("answer_text") or "").strip() or "OK"

    # blocked by quota / requires upgrade
    return (result.get("message") or "Sorry — you cannot use AI right now. Please try again.").strip()
