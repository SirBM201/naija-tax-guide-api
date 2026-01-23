# app/routes/telegram_routes.py
from flask import Blueprint, request, jsonify
import logging

from app.core.config import TELEGRAM_WEBHOOK_SECRET
from app.services.engine import resolve_answer
from app.services.telegram import telegram_send_message

bp = Blueprint("telegram", __name__)

@bp.post("/telegram/webhook/<secret>")
def telegram_webhook(secret: str):
    # Protect webhook URL
    if TELEGRAM_WEBHOOK_SECRET and secret != TELEGRAM_WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "invalid webhook secret"}), 401

    update = request.get_json(silent=True) or {}

    msg_obj = update.get("message") or {}
    text = msg_obj.get("text") or ""
    chat = msg_obj.get("chat") or {}
    chat_id = chat.get("id")

    # Ignore non-text updates safely (edited_message, callback_query, etc.)
    if not text or not chat_id:
        return jsonify({"ok": True, "ignored": True})

    logging.info("TG chat_id=%s msg=%s", chat_id, str(text)[:200])

    # Map telegram user -> wa_phone later.
    # For now, use chat_id as identifier so subscription/quota logic still works.
    wa_phone = str(chat_id)

    # NEVER let webhook crash; always return 200 to Telegram.
    try:
        res = resolve_answer(
            wa_phone=wa_phone,
            question=str(text),
            mode="text",
            lang="en",
            source="telegram",
        )

        # Your engine might return answer_text or answer; support both.
        answer_text = res.get("answer_text") or res.get("answer") or "Sorry, I could not generate an answer."
    except Exception as e:
        logging.exception("Telegram resolve_answer failed: %s", e)
        answer_text = "Sorry — the system had an error. Please try again in a moment."

    sent = telegram_send_message(chat_id, answer_text)

    # This JSON is for debugging only (Telegram does not show it to user).
    return jsonify({"ok": True, "sent": sent})
