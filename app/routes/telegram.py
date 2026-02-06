# app/routes/telegram.py

from __future__ import annotations

import os
import requests
from flask import Blueprint, request, jsonify

from app.services.channel_linking_service import extract_code, consume_and_link

bp = Blueprint("telegram", __name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")


def _tg_send(chat_id: int, text: str):
    if not TELEGRAM_BOT_TOKEN:
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    requests.post(url, json={
        "chat_id": chat_id,
        "text": text
    })


@bp.post("/telegram/webhook")
def webhook():

    payload = request.get_json(silent=True) or {}

    msg = payload.get("message", {})
    text = msg.get("text", "")

    chat_id = msg.get("chat", {}).get("id")
    user_id = msg.get("from", {}).get("id")

    if not chat_id or not user_id:
        return jsonify({"ok": True})

    code = extract_code(text)

    if not code:
        _tg_send(chat_id, "Send your linking code.\nExample: ABC23456")
        return jsonify({"ok": True})

    result = consume_and_link(
        provider="tg",
        code=code,
        provider_user_id=str(user_id)
    )

    if result["ok"]:
        _tg_send(chat_id, "✅ Telegram linked successfully.")
    else:
        _tg_send(chat_id, "❌ Invalid or expired code.")

    return jsonify({"ok": True})
