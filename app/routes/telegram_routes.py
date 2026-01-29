# app/routes/telegram_routes.py
import os
import logging
import requests
from flask import Blueprint, request, jsonify, current_app

bp = Blueprint("telegram", __name__)
log = logging.getLogger(__name__)

BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
WEBHOOK_TOKEN = (os.getenv("TELEGRAM_WEBHOOK_TOKEN") or "").strip()  # set this to match the token in your webhook URL

API = f"https://api.telegram.org/bot{BOT_TOKEN}"


def _send(chat_id: str, text: str) -> None:
    if not BOT_TOKEN:
        log.warning("TELEGRAM_BOT_TOKEN not set")
        return
    try:
        requests.post(f"{API}/sendMessage", json={"chat_id": chat_id, "text": text}, timeout=20)
    except Exception:
        log.exception("Telegram send failed")


def _handle_update(data: dict) -> dict:
    msg = data.get("message") or data.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id") or "")
    text = (msg.get("text") or "").strip()

    if not chat_id or not text:
        return {"ok": True, "ignored": True}

    # Call /ask internally using NEW format
    client = current_app.test_client()
    r = client.post(
        "/ask",
        json={
            "provider": "tg",
            "provider_user_id": chat_id,
            "question": text,
            "mode": "text",
            "lang": "en",
        },
    )
    j = r.get_json(silent=True) or {}
    answer = j.get("answer") or j.get("message") or "Sorry, I couldn't process that."

    _send(chat_id, answer)
    return {"ok": True}


@bp.post("/telegram/webhook")
def telegram_webhook_plain():
    data = request.get_json(silent=True) or {}
    return jsonify(_handle_update(data))


@bp.post("/telegram/webhook/<token>")
def telegram_webhook_token(token: str):
    # If you configured Telegram webhook URL with a token, validate it here
    if WEBHOOK_TOKEN and token != WEBHOOK_TOKEN:
        return jsonify({"ok": False, "message": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    return jsonify(_handle_update(data))
