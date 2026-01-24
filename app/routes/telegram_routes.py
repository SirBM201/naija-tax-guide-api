# app/routes/telegram_routes.py
from flask import Blueprint, request, jsonify
import logging
import requests

from app.core.config import TELEGRAM_WEBHOOK_SECRET, TELEGRAM_BOT_TOKEN
from app.services.engine import resolve_answer

bp = Blueprint("telegram", __name__)

def tg_send_message(chat_id: int, text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN:
        logging.error("TELEGRAM_BOT_TOKEN not set; cannot reply to Telegram.")
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
        return True
    except Exception as e:
        logging.exception("Telegram sendMessage exception: %s", str(e))
        return False


@bp.post("/telegram/webhook/<secret>")
def telegram_webhook(secret: str):
    # Enforce only if you actually configured TELEGRAM_WEBHOOK_SECRET in Koyeb env
    if TELEGRAM_WEBHOOK_SECRET and secret != TELEGRAM_WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "invalid webhook secret"}), 401

    update = request.get_json(silent=True) or {}
    msg_obj = update.get("message") or {}
    msg_text = (msg_obj.get("text") or "").strip()
    chat = msg_obj.get("chat") or {}
    chat_id = chat.get("id")

    # ignore non-message updates safely
    if not msg_text or not chat_id:
        return jsonify({"ok": True, "ignored": True})

    logging.info("TG chat_id=%s msg=%s", chat_id, msg_text[:200])

    # Use chat_id as identity for now (later you can map Telegram user -> wa_phone)
    wa_phone = str(chat_id)

    res = resolve_answer(
        wa_phone=wa_phone,
        question=msg_text,
        mode="text",
        lang="en",
        source="telegram",
    )

    answer_text = res.get("answer_text") or res.get("answer") or "OK."
    sent = tg_send_message(int(chat_id), answer_text)

    return jsonify({"ok": True, "sent": sent})
