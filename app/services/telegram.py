# app/services/telegram.py
import logging
import requests

from app.core.config import TELEGRAM_BOT_TOKEN

def telegram_send_message(chat_id: int | str, text: str) -> bool:
    """
    Sends a Telegram message using Bot API.
    Telegram webhook responses are NOT shown to users; you must call sendMessage.
    """
    if not TELEGRAM_BOT_TOKEN:
        logging.warning("TELEGRAM_BOT_TOKEN not set; cannot send Telegram messages")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }

    try:
        r = requests.post(url, json=payload, timeout=20)
        if r.status_code != 200:
            logging.error("Telegram sendMessage failed: status=%s body=%s", r.status_code, r.text[:400])
            return False

        js = r.json() or {}
        ok = js.get("ok") is True
        if not ok:
            logging.error("Telegram sendMessage not ok: body=%s", str(js)[:400])
        return ok
    except Exception as e:
        logging.exception("Telegram sendMessage exception: %s", e)
        return False
