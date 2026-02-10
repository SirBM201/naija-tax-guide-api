# app/services/outbound_service.py
import os
import logging
from typing import Optional, Dict, Any

import requests

log = logging.getLogger(__name__)

# ---------------------------
# WhatsApp (Meta Cloud API)
# ---------------------------
WHATSAPP_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WHATSAPP_VERSION = os.getenv("WHATSAPP_VERSION", "v20.0").strip()
META_GRAPH_BASE = os.getenv("META_GRAPH_BASE", "https://graph.facebook.com").strip()

# ---------------------------
# Telegram
# ---------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()


def send_whatsapp_text(to_wa_id: str, text: str) -> Dict[str, Any]:
    """
    Sends a WhatsApp text message via Meta Cloud API.
    Requires:
      WHATSAPP_ACCESS_TOKEN
      WHATSAPP_PHONE_NUMBER_ID
    """
    to_wa_id = (to_wa_id or "").strip()
    text = (text or "").strip()
    if not to_wa_id or not text:
        return {"ok": False, "error": "missing_to_or_text"}

    if not WHATSAPP_ACCESS_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        return {"ok": False, "error": "missing_whatsapp_env_vars"}

    url = f"{META_GRAPH_BASE}/{WHATSAPP_VERSION}/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_id,
        "type": "text",
        "text": {"body": text},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code >= 200 and r.status_code < 300:
            return {"ok": True, "status": r.status_code, "data": r.json()}
        return {"ok": False, "status": r.status_code, "error": r.text}
    except Exception as e:
        log.exception("send_whatsapp_text failed: %s", e)
        return {"ok": False, "error": str(e)}


def send_telegram_text(chat_id: str, text: str) -> Dict[str, Any]:
    """
    Sends a Telegram message via Bot API.
    Requires:
      TELEGRAM_BOT_TOKEN
    """
    chat_id = (chat_id or "").strip()
    text = (text or "").strip()
    if not chat_id or not text:
        return {"ok": False, "error": "missing_chat_id_or_text"}

    if not TELEGRAM_BOT_TOKEN:
        return {"ok": False, "error": "missing_telegram_bot_token"}

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}

    try:
        r = requests.post(url, json=payload, timeout=20)
        if r.status_code >= 200 and r.status_code < 300:
            return {"ok": True, "status": r.status_code, "data": r.json()}
        return {"ok": False, "status": r.status_code, "error": r.text}
    except Exception as e:
        log.exception("send_telegram_text failed: %s", e)
        return {"ok": False, "error": str(e)}
