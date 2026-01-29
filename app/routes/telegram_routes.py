# app/routes/telegram_routes.py
import os
import logging
import requests
from flask import Blueprint, request, jsonify, current_app

bp = Blueprint("telegram", __name__)
log = logging.getLogger(__name__)

BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
WEBHOOK_TOKEN = (os.getenv("TELEGRAM_WEBHOOK_TOKEN") or "").strip()  # optional: must match <token> in URL if used

API = f"https://api.telegram.org/bot{BOT_TOKEN}"


def _send(chat_id: str, text: str) -> None:
    """Send message back to Telegram chat."""
    if not BOT_TOKEN:
        log.warning("TELEGRAM_BOT_TOKEN not set")
        return

    try:
        requests.post(
            f"{API}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=20,
        )
    except Exception:
        log.exception("Telegram send failed")


def _extract_update(data: dict) -> tuple[str, str]:
    """
    Returns (chat_id, text). If not a text message, returns ("","").
    """
    msg = data.get("message") or data.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id") or "").strip()
    text = (msg.get("text") or "").strip()
    return chat_id, text


def _call_internal_ask(chat_id: str, text: str) -> dict:
    """
    Calls /ask internally (same Flask app) using the NEW format.
    """
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
    return r.get_json(silent=True) or {}


def _handle_update(data: dict) -> dict:
    chat_id, text = _extract_update(data)

    if not chat_id or not text:
        return {"ok": True, "ignored": True}

    try:
        j = _call_internal_ask(chat_id, text)

        # /ask response may be ok=true or ok=false
        if j.get("ok") is True:
            answer = j.get("answer") or "OK."
        else:
            # blocked/quota/errors still return a helpful message
            answer = j.get("message") or "Sorry, I couldn't process that right now."

        _send(chat_id, answer)
        return {"ok": True}

    except Exception:
        log.exception("telegram handler failed")
        _send(chat_id, "Sorry — system error. Please try again in a moment.")
        return {"ok": True, "error": True}


# -----------------------------
# Routes
# -----------------------------
@bp.get("/telegram/health")
def telegram_health():
    return jsonify({"ok": True, "service": "telegram", "bot_token_set": bool(BOT_TOKEN)}), 200


@bp.post("/telegram/webhook")
def telegram_webhook_plain():
    data = request.get_json(silent=True) or {}
    return jsonify(_handle_update(data)), 200


@bp.post("/telegram/webhook/<token>")
def telegram_webhook_token(token: str):
    # If you configured Telegram webhook URL with a token, validate it here
    if WEBHOOK_TOKEN and token != WEBHOOK_TOKEN:
        return jsonify({"ok": False, "message": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    return jsonify(_handle_update(data)), 200
