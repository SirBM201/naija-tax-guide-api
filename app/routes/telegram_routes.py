# app/routes/telegram_routes.py
import logging
from flask import Blueprint, request, jsonify

from app.core.config import TELEGRAM_WEBHOOK_SECRET
from app.services.engine import resolve_answer
from app.services.telegram import (
    telegram_send_message_ex,
    telegram_request_phone_keyboard,
    extract_telegram_phone,
    extract_telegram_chat_id,
    extract_telegram_text,
)

bp = Blueprint("telegram", __name__)


@bp.get("/telegram/health")
def telegram_health():
    return jsonify({"ok": True, "service": "telegram"}), 200


@bp.post("/telegram/webhook")
def telegram_webhook():
    # Telegram sends the secret in this header when you setWebhook(secret_token=...)
    provided = (request.headers.get("X-Telegram-Bot-Api-Secret-Token") or "").strip()

    if TELEGRAM_WEBHOOK_SECRET:
        if not provided or provided != TELEGRAM_WEBHOOK_SECRET:
            logging.warning(
                "Telegram secret header mismatch. provided=%r expected=%r",
                provided, TELEGRAM_WEBHOOK_SECRET
            )
            return jsonify({"ok": False}), 401

    update = request.get_json(silent=True) or {}

    chat_id = extract_telegram_chat_id(update)
    text = extract_telegram_text(update)

    if not chat_id:
        return jsonify({"ok": True}), 200

    # ignore non-text updates
    if not text:
        return jsonify({"ok": True}), 200

    logging.info("TG inbound chat_id=%s text=%s", chat_id, text[:200])

    # IMPORTANT: Use phone identity for unified quota across WhatsApp/Telegram/Web.
    # Telegram does not always provide phone; we request it if missing.
    phone = extract_telegram_phone(update)

    if not phone:
        telegram_send_message_ex(
            chat_id=chat_id,
            text=(
                "To use Naija Tax Guide on Telegram, please share your phone number once.\n\n"
                "This helps us link your plan and AI credits across WhatsApp, Telegram, and Web."
            ),
            reply_markup=telegram_request_phone_keyboard(),
        )
        return jsonify({"ok": True}), 200

    # Now phone is our unified identity key (same as WhatsApp wa_phone)
    res = resolve_answer(
        wa_phone=str(phone),
        question=text,
        mode="text",
        lang="en",
        source="telegram",
    )

    if not res.get("ok"):
        msg = res.get("message") or "Unable to process. Please try again."
        telegram_send_message_ex(chat_id=chat_id, text=msg)
        return jsonify({"ok": True}), 200

    answer = res.get("answer_text") or "OK"
    telegram_send_message_ex(chat_id=chat_id, text=answer)

    return jsonify({"ok": True}), 200
