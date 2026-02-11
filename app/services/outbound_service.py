# app/services/outbound_service.py
from __future__ import annotations

import os
import logging
import requests
from typing import Optional, List

# -----------------------------
# WhatsApp Cloud API
# -----------------------------
WA_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WA_API_BASE = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"

# -----------------------------
# Telegram Bot API
# -----------------------------
TG_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TG_API_BASE = f"https://api.telegram.org/bot{TG_BOT_TOKEN}"

# Safe message chunk size (WhatsApp/Telegram both handle long, but chunking is safer UX)
MAX_CHUNK = 1200


def _chunk_text(text: str, max_len: int = MAX_CHUNK) -> List[str]:
    t = (text or "").strip()
    if not t:
        return []
    if len(t) <= max_len:
        return [t]

    chunks: List[str] = []
    start = 0
    while start < len(t):
        end = min(start + max_len, len(t))
        # try to break on newline/space for better readability
        slice_ = t[start:end]
        cut = max(slice_.rfind("\n"), slice_.rfind(" "))
        if cut > 200:  # avoid tiny cuts
            end = start + cut
            slice_ = t[start:end]
        chunks.append(slice_.strip())
        start = end
    return [c for c in chunks if c]


# -------------------------------------------------
# WhatsApp outbound
# -------------------------------------------------
def send_whatsapp_text(to_phone: str, text: str, *, preview_url: bool = False) -> bool:
    if not (WA_ACCESS_TOKEN and WA_PHONE_NUMBER_ID):
        logging.warning("WhatsApp env not set (WHATSAPP_ACCESS_TOKEN/WHATSAPP_PHONE_NUMBER_ID)")
        return False

    to_phone = (to_phone or "").strip()
    if not to_phone:
        return False

    headers = {
        "Authorization": f"Bearer {WA_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }

    ok_any = False
    for part in _chunk_text(text):
        payload = {
            "messaging_product": "whatsapp",
            "to": to_phone,
            "type": "text",
            "text": {"preview_url": bool(preview_url), "body": part},
        }
        try:
            r = requests.post(WA_API_BASE, json=payload, headers=headers, timeout=20)
            if r.status_code >= 300:
                logging.warning("WA send failed: %s %s", r.status_code, r.text)
            else:
                ok_any = True
        except Exception as e:
            logging.exception("WA send exception: %s", e)

    return ok_any


# -------------------------------------------------
# Telegram outbound
# -------------------------------------------------
def send_telegram_text(chat_id: str | int, text: str) -> bool:
    if not TG_BOT_TOKEN:
        logging.warning("Telegram env not set (TELEGRAM_BOT_TOKEN)")
        return False

    cid = str(chat_id or "").strip()
    if not cid:
        return False

    ok_any = False
    for part in _chunk_text(text):
        try:
            r = requests.post(
                f"{TG_API_BASE}/sendMessage",
                json={"chat_id": cid, "text": part},
                timeout=20,
            )
            if r.status_code >= 300:
                logging.warning("TG send failed: %s %s", r.status_code, r.text)
            else:
                ok_any = True
        except Exception as e:
            logging.exception("TG send exception: %s", e)

    return ok_any
