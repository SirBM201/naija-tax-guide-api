# app/routes/telegram_routes.py

import os
import logging
from flask import Blueprint, request, jsonify

from services.telegram import tg_send_message
from message_router import route_message

telegram_bp = Blueprint("telegram", __name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

def _safe_str(x) -> str:
    return "" if x is None else str(x)

@telegram_bp.post("/telegram/webhook/<secret>")
def telegram_webhook(secret: str):
    """
    Telegram will POST updates here.
    Must respond FAST with 200 or Telegram will retry and/or mark webhook unhealthy.
    """
    if not TELEGRAM_WEBHOOK_SECRET or secret != TELEGRAM_WEBHOOK_SECRET:
        return "forbidden", 403

    update = request.get_json(silent=True) or {}

    # Always acknowledge quickly even if update is not a message
    msg = (update.get("message") or update.get("edited_message") or {}) or {}
    chat = (msg.get("chat") or {}) or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()

    # Not a text message or no chat_id -> OK
    if not chat_id:
        return "ok", 200

    # /start support
    if text.lower().startswith("/start"):
        tg_send_message(chat_id, "✅ Naija Hustle Tax Guide is connected.\n\nSend your tax question here.")
        return "ok", 200

    # Ignore empty
    if not text:
        tg_send_message(chat_id, "Please type your question.")
        return "ok", 200

    try:
        sender_key = f"tg:{_safe_str(chat_id)}"
        reply = route_message(sender_key, text)
        tg_send_message(chat_id, reply)
    except Exception as e:
        logging.exception("Telegram inbound handling failed: %s", e)
        tg_send_message(chat_id, "Sorry — an error occurred. Please try again.")

    return "ok", 200


@telegram_bp.get("/telegram/ping")
def telegram_ping():
    """
    Simple health check to confirm this blueprint is registered.
    """
    return jsonify({"ok": True, "telegram": True}), 200
