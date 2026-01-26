# message_router.py

from typing import Optional

from app.services.session_service import (
    get_active_session,
    create_session,
    update_session,
    close_session,
)

from flows import paye_flow


# -----------------------------
# Flow detection
# -----------------------------
def detect_flow_key(text: str) -> Optional[str]:
    t = (text or "").strip().lower()

    if any(k in t for k in ["paye", "pay as you earn", "salary tax", "employee tax"]):
        return "paye"

    # Future flows:
    # if "vat" in t: return "vat"
    # if "withholding" in t or "wht" in t: return "wht"

    return None


# -----------------------------
# Central router
# -----------------------------
def route_message(sender_key: str, text: str) -> str:
    """
    sender_key examples:
      - wa:234xxxxxxxxxx
      - tg:123456789

    This keeps WhatsApp, Telegram, Web unified.
    """

    clean_text = (text or "").strip()
    if not clean_text:
        return "Please type your question."

    # 1) Continue active session if exists
    session = get_active_session(sender_key)

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

    # 2) Detect new flow
    flow_key = detect_flow_key(clean_text)

    if flow_key == "paye":
        create_session(sender_key, "paye", "ASK_INCOME")
        return paye_flow.start()

    # 3) Fallback → AI / tax engine
    from app.services.engine import answer_engine_reply

    return answer_engine_reply(sender_key, clean_text)
