# app/routes/telegram_routes.py
import logging
from flask import Blueprint, request, jsonify

from app.core.config import TELEGRAM_WEBHOOK_SECRET
from app.services.engine import resolve_answer

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

    msg = (update.get("message") or {})
    chat = (msg.get("chat") or {})
    chat_id = chat.get("id")

    text = (msg.get("text") or "").strip()
    if not chat_id or not text:
        # Nothing to do (could be sticker/photo/etc.)
        return jsonify({"ok": True}), 200

    logging.info("TG inbound chat_id=%s text=%s", chat_id, text[:200])

    # For now, reuse engine without requiring wa_phone
    # We'll pass chat_id as identity so you still get caching/library lookup.
    res = resolve_answer(
        wa_phone=str(chat_id),
        question=text,
        mode="text",
        lang="en",
        source="telegram",
    )

    # IMPORTANT:
    # This route should just return 200 quickly.
    # Your actual "sendMessage" call to Telegram can be elsewhere in your code.
    # If you already have a Telegram send function, call it here.
    #
    # Example placeholder: you must replace with your existing send logic.
    answer = res.get("answer_text") or "OK"

    # If you already have a working Telegram sender, call it now.
    # Otherwise keep returning 200 so webhook doesn't fail.
    try:
        from app.services.telegram_send import send_telegram_message  # if you have it
        send_telegram_message(chat_id=str(chat_id), text=answer)
    except Exception:
        logging.exception("Telegram send failed or telegram_send not present (webhook still OK).")

    return jsonify({"ok": True}), 200
