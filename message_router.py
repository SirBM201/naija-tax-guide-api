# message_router.py (repo root)

from typing import Optional

from services.session_service import (
    get_active_session,
    create_session,
    update_session,
    close_session,
)

from flows import paye_flow

# -----------------------------
# Flow selection (extend later)
# -----------------------------
def detect_flow_key(text: str) -> Optional[str]:
    t = (text or "").strip().lower()

    # PAYE intent
    if any(k in t for k in ["paye", "pay as you earn", "salary tax", "employee tax"]):
        return "paye"

    # Extend later:
    # if "vat" in t: return "vat"
    # if "withholding" in t or "wht" in t: return "wht"

    return None


def route_message(sender_key: str, text: str) -> str:
    """
    Central router used by WhatsApp/web/Telegram entrypoints.

    sender_key:
      - WhatsApp: use normalized phone e.g. "234xxxxxxxxxx"
      - Telegram: use "tg:<chat_id>" (until you implement phone linking)
    """

    clean_text = (text or "").strip()
    if not clean_text:
        return "Please type your question."

    # 1) Continue active session if exists
    # NOTE: current implementation checks PAYE session only.
    existing_flow_key = "paye"
    session = get_active_session(sender_key, existing_flow_key)

    if session:
        result = paye_flow.handle(session["state"], clean_text, session)

        if result.get("next_state") == "DONE":
            close_session(session["id"])
        else:
            update_session(
                session["id"],
                state=result["next_state"],
                step=(session.get("step") or 0) + 1,
                data=result.get("data"),
            )

        return result["reply"]

    # 2) No session: detect flow
    flow_key = detect_flow_key(clean_text)
    if flow_key == "paye":
        create_session(sender_key, "paye", "ASK_INCOME")
        return paye_flow.start()

    # 3) No flow matched -> general engine
    # Import lazily to avoid circular imports.
    from services.engine import answer_engine_reply

    return answer_engine_reply(sender_key, clean_text)
