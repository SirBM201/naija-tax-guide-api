# services/telegram.py

import os
import logging
import requests

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()


def tg_send_message(chat_id: int, text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN:
        logging.error("TELEGRAM_BOT_TOKEN not set")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text or "",
        "disable_web_page_preview": True,
    }

    try:
        r = requests.post(url, json=payload, timeout=15)
        if 200 <= r.status_code < 300:
            return True
        logging.error("Telegram sendMessage failed %s: %s", r.status_code, r.text)
        return False
    except Exception as e:
        logging.exception("Telegram sendMessage exception: %s", e)
        return False
