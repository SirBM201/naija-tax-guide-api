import requests
from .config import settings

GRAPH_URL = "https://graph.facebook.com/v20.0"

def send_whatsapp_text(to_phone: str, text: str) -> None:
    """
    Sends a WhatsApp text message via Cloud API.
    Will work only when Meta fully enables messaging for your WABA.
    """
    url = f"{GRAPH_URL}/{settings.WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {settings.WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text[:4000]},
    }
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    # If still pending/in review, Meta may return error; do not crash server.
    if not r.ok:
        print("WhatsApp send failed:", r.status_code, r.text)
