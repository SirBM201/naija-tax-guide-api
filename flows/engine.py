from datetime import datetime, timedelta
from flows.registry import FLOW_REGISTRY

def resolve_flow(message_text: str):
    text = message_text.lower()

    if "paye" in text:
        return "paye"
    if "vat" in text:
        return "vat"
    if "business" in text or "hustle" in text:
        return "hustler_onboarding"

    return None
