# app/routes/telegram.py
from __future__ import annotations

import os
import logging
import requests
from flask import Blueprint, request, jsonify

from app.services.channel_linking_service import extract_code, consume_and_link

bp = Blueprint("telegram", __name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_BOT_USERNAME = os.getenv("TELEGRAM_BOT_USERNAME", "naija_tax_guide_bot").strip()


def _tg_send(chat_id: int, text: str) -> None:
    if not TELEGRAM_BOT_TOKEN:
        logging.warning("TELEGRAM_BOT_TOKEN not set; cannot send reply")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=10)
    except Exception as e:
        logging.warning("Failed to send TG message: %s", e)


@bp.post("/telegram/webhook")
def telegram_webhook():
    payload = request.get_json(silent=True) or {}

    msg = payload.get("message") or payload.get("edited_message") or {}
    text = (msg.get("text") or "").strip()

    chat = msg.get("chat") or {}
    chat_id = chat.get("id")

    from_user = msg.get("from") or {}
    tg_user_id = from_user.get("id")  # numeric
    display_name = " ".join(
        [p for p in [(from_user.get("first_name") or "").strip(), (from_user.get("last_name") or "").strip()] if p]
    ).strip() or None
    username = (from_user.get("username") or "").strip() or None

    if not chat_id or not tg_user_id:
        return jsonify({"ok": True})

    code = extract_code(text)

    if not code:
        if text.lower().startswith("/start"):
            _tg_send(
                chat_id,
                "Welcome 👋\n\nTo link Telegram, send your 6–12 character code.\n\nExample:\nABC12345\n(or /start ABC12345)",
            )
        return jsonify({"ok": True})

    provider_user_id = str(tg_user_id)

    result = consume_and_link(
        provider="tg",
        code=code,
        provider_user_id=provider_user_id,
        display_name=display_name or username,
        phone=None,
    )

    if result.get("ok"):
        _tg_send(chat_id, "✅ Linked successfully!\n\nYour Telegram is now connected to your Naija Tax Guide account.")
    else:
        _tg_send(chat_id, "❌ Link failed.\n\nInvalid/expired code OR already used. Generate a new code and try again.")

    return jsonify({"ok": True})
