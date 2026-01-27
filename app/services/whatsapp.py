# app/services/whatsapp.py
import os
import logging
import requests

WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WHATSAPP_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()

GRAPH_API_BASE = "https://graph.facebook.com/v20.0"


def wa_send_text(to_phone: str, text: str) -> bool:
    """
    Send WhatsApp text message via Cloud API.
    to_phone should be E.164 format without '+' sometimes works, but use +234... style if possible.
    """
    if not WHATSAPP_PHONE_NUMBER_ID or not WHATSAPP_ACCESS_TOKEN:
        logging.error("WA send blocked: WHATSAPP_PHONE_NUMBER_ID / WHATSAPP_ACCESS_TOKEN not set")
        return False

    url = f"{GRAPH_API_BASE}/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text or "", "preview_url": False},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if 200 <= r.status_code < 300:
            return True
        logging.error("WA send failed %s: %s", r.status_code, r.text)
        return False
    except Exception as e:
        logging.exception("WA send exception: %s", e)
        return False
