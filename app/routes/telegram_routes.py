# app/routes/telegram_routes.py
from flask import Blueprint, request, jsonify
import os
import logging

from app.core.config import TELEGRAM_WEBHOOK_SECRET
from app.services.engine import resolve_answer

bp = Blueprint("telegram", __name__)

@bp.post("/telegram/webhook/<secret>")
def telegram_webhook(secret: str):
    # Basic protection: URL secret must match env secret (recommended)
    if TELEGRAM_WEBHOOK_SECRET and secret != TELEGRAM_WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "invalid webhook secret"}), 401

    update = request.get_json(silent=True) or {}
    msg = (update.get("message") or {}).get("text") or ""
    chat = (update.get("message") or {}).get("chat") or {}
    chat_id = chat.get("id")

    # If Telegram sends something else (edited_message, callback_query), ignore safely
    if not msg or not chat_id:
        return jsonify({"ok": True, "ignored": True})

    logging.info("TG chat_id=%s msg=%s", chat_id, str(msg)[:200])

    # In your system, map telegram user -> wa_phone later.
    # For now, use chat_id as an identifier to keep pipeline working.
    wa_phone = str(chat_id)

    res = resolve_answer(
        wa_phone=wa_phone,
        question=str(msg),
        mode="text",
        lang="en",
        source="telegram",
    )

    # You likely have a Telegram send-message function elsewhere.
    # For now we return the computed answer so you can confirm the webhook works.
    return jsonify({"ok": True, "answer": res.get("answer_text")})
