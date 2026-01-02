def can_use_flow(plan, flow_key):
    FREE_LIMITED = ["hustler_onboarding"]

    if plan == "free" and flow_key not in FREE_LIMITED:
        return False

    return True

if not can_use_flow(user_plan, flow_key):
    send_reply(
        "🔒 This feature requires a paid plan.\n"
        "Reply *UPGRADE* to continue."
    )
    return
