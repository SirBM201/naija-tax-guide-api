# app/routes/telegram_routes.py
from flask import Blueprint, request, jsonify
import logging

from app.core.config import TELEGRAM_WEBHOOK_SECRET
from app.services.engine import resolve_answer
from app.services.telegram import telegram_send_message

bp = Blueprint("telegram", __name__)

@bp.post("/telegram/webhook/<secret>")
def telegram_webhook(secret: str):
    # Permanent protection: secret in URL must match env var
    if not TELEGRAM_WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "server not configured (missing TELEGRAM_WEBHOOK_SECRET)"}), 500

    if secret != TELEGRAM_WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "invalid webhook secret"}), 401

    update = request.get_json(silent=True) or {}

    msg_obj = update.get("message") or {}
    text = msg_obj.get("text") or ""
    chat = msg_obj.get("chat") or {}
    chat_id = chat.get("id")

    # Ignore non-text updates safely
    if not text or not chat_id:
        return jsonify({"ok": True, "ignored": True})

    logging.info("TG chat_id=%s msg=%s", chat_id, str(text)[:200])

    # Use chat_id as user identity for now
    wa_phone = str(chat_id)

    try:
        res = resolve_answer(
            wa_phone=wa_phone,
            question=text,
            mode="text",
            lang="en",
            source="telegram",
        )
        answer_text = res.get("answer_text") or "Sorry, I could not generate an answer."
    except Exception as e:
        logging.exception("Telegram resolve_answer failed: %s", e)
        answer_text = "Sorry — something went wrong. Please try again."

    sent = telegram_send_message(chat_id, answer_text)
    return jsonify({"ok": True, "sent": sent})
