# message_router.py
from app.services.engine import resolve_answer


def route_message(sender_key: str, text: str) -> str:
    """
    Central router used by Telegram/WhatsApp/Web.
    Option 1: no sessions, always resolve via the engine.

    sender_key examples:
      - tg:123456789
      - wa:234xxxxxxxxxx
    """
    clean_text = (text or "").strip()
    if not clean_text:
        return "Please type your question."

    result = resolve_answer(
        wa_phone=sender_key,          # engine uses this as identity key
        question=clean_text,
        mode="text",
        lang="en",
        source="telegram",            # good for logging/analytics
    )

    # Engine can return ok=False when quota is blocked
    if not result.get("ok"):
        return result.get("message") or "Sorry — you cannot use AI right now."

    return result.get("answer_text") or "OK"
