# app/services/outbound_service.py
from __future__ import annotations

import os
import logging
import requests


# -------------------------
# WhatsApp (Meta Cloud)
# -------------------------
WA_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WA_API_BASE = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"


def send_whatsapp_text(to_phone: str, text: str) -> bool:
    to_phone = (to_phone or "").strip()
    text = (text or "").strip()
    if not to_phone or not text:
        return False

    if not (WA_ACCESS_TOKEN and WA_PHONE_NUMBER_ID):
        logging.warning("WhatsApp env not set (WHATSAPP_ACCESS_TOKEN/WHATSAPP_PHONE_NUMBER_ID)")
        return False

    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"preview_url": False, "body": text},
    }
    headers = {"Authorization": f"Bearer {WA_ACCESS_TOKEN}", "Content-Type": "application/json"}

    try:
        r = requests.post(WA_API_BASE, json=payload, headers=headers, timeout=15)
        if r.status_code >= 300:
            logging.warning("WA send failed: %s %s", r.status_code, r.text)
            return False
        return True
    except Exception as e:
        logging.exception("WA send exception: %s", e)
        return False


# -------------------------
# Telegram
# -------------------------
TG_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TG_API = f"https://api.telegram.org/bot{TG_BOT_TOKEN}"


def send_telegram_text(chat_id: str, text: str) -> bool:
    chat_id = str(chat_id or "").strip()
    text = (text or "").strip()
    if not chat_id or not text:
        return False

    if not TG_BOT_TOKEN:
        logging.warning("Telegram env not set (TELEGRAM_BOT_TOKEN)")
        return False

    try:
        r = requests.post(
            f"{TG_API}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=15,
        )
        if r.status_code >= 300:
            logging.warning("TG send failed: %s %s", r.status_code, r.text)
            return False
        return True
    except Exception as e:
        logging.exception("TG send exception: %s", e)
        return False
