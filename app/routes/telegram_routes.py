# app/routes/telegram_routes.py
from flask import Blueprint, request, jsonify
import logging
import requests

from app.core.config import TELEGRAM_WEBHOOK_SECRET, TELEGRAM_BOT_TOKEN
from app.services.engine import resolve_answer

bp = Blueprint("telegram", __name__)

def telegram_send_message(chat_id: str, text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN:
        logging.error("TELEGRAM_BOT_TOKEN not set")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }

    try:
        r = requests.post(url, json=payload, timeout=15)
        if r.status_code >= 300:
            logging.error("TG sendMessage failed: %s %s", r.status_code, r.text[:500])
            return False
        return True
    except Exception as e:
        logging.exception("TG sendMessage exception: %s", e)
        return False

@bp.post("/telegram/webhook/<secret>")
def telegram_webhook(secret: str):
    # Basic protection
    if TELEGRAM_WEBHOOK_SECRET and secret != TELEGRAM_WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "invalid webhook secret"}), 401

    update = request.get_json(silent=True) or {}

    # Telegram may send message, edited_message, callback_query, etc.
    message = update.get("message") or update.get("edited_message") or {}
    msg_text = (message.get("text") or "").strip()
    chat = message.get("chat") or {}
    chat_id = chat.get("id")

    if not msg_text or not chat_id:
        return jsonify({"ok": True, "ignored": True})

    chat_id_str = str(chat_id)
    logging.info("TG chat_id=%s msg=%s", chat_id_str, msg_text[:200])

    # Using chat_id as identifier for now (later you can map Telegram user -> wa_phone)
    wa_phone = chat_id_str

    res = resolve_answer(
        wa_phone=wa_phone,
        question=msg_text,
        mode="text",
        lang="en",
        source="telegram",
    )

    answer_text = res.get("answer_text") or "No answer available."

    # Send back to Telegram user
    sent = telegram_send_message(chat_id_str, answer_text)

    # Always return 200 OK to Telegram so it won't keep retrying
    return jsonify({"ok": True, "sent": sent})
