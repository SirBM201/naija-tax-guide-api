from services.session_service import (
    get_active_session,
    create_session,
    update_session,
    close_session
)
from flows import paye_flow


def route_message(phone, text):
    flow_key = "paye"  # default for now

    session = get_active_session(phone, flow_key)

    if not session:
        create_session(phone, flow_key, "ASK_INCOME")
        return paye_flow.start()

    result = paye_flow.handle(session["state"], text, session)

    if result["next_state"] == "DONE":
        close_session(session["id"])
    else:
        update_session(
            session["id"],
            state=result["next_state"],
            step=session["step"] + 1,
            data=result.get("data")
        )

    return result["reply"]
