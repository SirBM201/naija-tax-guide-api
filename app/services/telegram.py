# app/services/telegram.py
import logging
import requests
from app.core.config import TELEGRAM_BOT_TOKEN

def telegram_send_message(chat_id: int | str, text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN:
        logging.error("TELEGRAM_BOT_TOKEN not set; cannot send Telegram messages")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }

    try:
        r = requests.post(url, json=payload, timeout=20)
        if r.status_code != 200:
            logging.error("Telegram sendMessage failed: %s %s", r.status_code, r.text[:300])
            return False

        data = r.json()
        return bool(data.get("ok"))
    except Exception as e:
        logging.exception("Telegram sendMessage exception: %s", e)
        return False
