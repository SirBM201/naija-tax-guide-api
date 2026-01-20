# message_router.py (repo root)

import re
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


def route_message(phone: str, text: str) -> str:
    """
    Central router used by WhatsApp/web entrypoints.
    - If a session exists -> continue that flow
    - Else detect which flow should start
    - Else fallback to general Q&A (ask endpoint / tax engine)
    """

    clean_text = (text or "").strip()
    if not clean_text:
        return "Please type your question."

    # 1) If user already has an active session, continue it
    #    (session has flow_key stored; if not, default to paye)
    existing_flow_key = "paye"
    session = get_active_session(phone, existing_flow_key)

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

    # 2) No session: detect flow based on message
    flow_key = detect_flow_key(clean_text)
    if flow_key == "paye":
        create_session(phone, "paye", "ASK_INCOME")
        return paye_flow.start()

    # 3) No flow matched -> fallback to general tax answer engine
    #    We import lazily to avoid circular imports.
    from app.main import answer_engine_reply

    return answer_engine_reply(phone, clean_text)
