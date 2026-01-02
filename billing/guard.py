def can_use_flow(plan, flow_key):
    FREE_LIMITED = ["hustler_onboarding"]

    if plan == "free" and flow_key not in FREE_LIMITED:
        return False

    return True
