from flask import Blueprint, request, jsonify
import logging
import requests
import os

bp = Blueprint("telegram", __name__)
log = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
API = f"https://api.telegram.org/bot{BOT_TOKEN}"


@bp.post("/telegram/webhook")
def telegram_webhook():
    data = request.get_json(silent=True) or {}
    msg = data.get("message") or {}

    chat = msg.get("chat") or {}
    chat_id = str(chat.get("id"))
    text = (msg.get("text") or "").strip()
    if not text:
        return jsonify(ok=True)

    # internal ask call
    from flask import current_app
    client = current_app.test_client()
    r = client.post("/ask", json={
        "provider": "tg",
        "provider_user_id": chat_id,
        "question": text,
    })
    answer = (r.get_json() or {}).get("answer") or "Sorry, try again."

    requests.post(f"{API}/sendMessage", json={
        "chat_id": chat_id,
        "text": answer,
    })

    return jsonify(ok=True)
