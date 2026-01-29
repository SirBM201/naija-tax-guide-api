# app/routes/telegram_routes.py
from flask import Blueprint, request, jsonify, current_app
import logging
import requests
import os

bp = Blueprint("telegram", __name__)
log = logging.getLogger(__name__)

BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
API = f"https://api.telegram.org/bot{BOT_TOKEN}"


def _tg_send(chat_id: str, text: str) -> None:
    if not BOT_TOKEN:
        log.error("TELEGRAM_BOT_TOKEN missing")
        return
    try:
        r = requests.post(
            f"{API}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=20
        )
        if r.status_code >= 300:
            log.error("Telegram send failed: %s %s", r.status_code, r.text[:500])
    except Exception:
        log.exception("Telegram send exception")


def _ask_engine_tg(chat_id: str, question: str) -> str:
    """
    Calls internal /ask using the new identity format.
    """
    try:
        client = current_app.test_client()
        resp = client.post("/ask", json={
            "provider": "tg",
            "provider_user_id": str(chat_id),
            "question": question,
            "mode": "text",
            "lang": "en",
        })
        data = resp.get_json(silent=True) or {}
        if data.get("ok") is True and data.get("answer"):
            return str(data["answer"])
        return str(data.get("message") or "Sorry, I couldn't process that right now.")
    except Exception:
        log.exception("Telegram engine call failed")
        return "Sorry — something went wrong. Please try again."


@bp.get("/telegram/ping")
def telegram_ping():
    return jsonify(ok=True, telegram=True, token_ok=bool(BOT_TOKEN))


# --- IMPORTANT ---
# Support BOTH webhook paths:
# 1) /telegram/webhook
# 2) /telegram/webhook/<anything>   (matches the old URL that includes a token)
@bp.post("/telegram/webhook")
@bp.post("/telegram/webhook/<path:_rest>")
def telegram_webhook(_rest: str = ""):
    data = request.get_json(silent=True) or {}

    msg = data.get("message") or data.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")

    text = (msg.get("text") or "").strip()
    if not chat_id or not text:
        return jsonify(ok=True, ignored=True)

    chat_id = str(chat_id)
    log.info("Telegram inbound chat_id=%s text=%s", chat_id, text[:200])

    answer = _ask_engine_tg(chat_id=chat_id, question=text)
    _tg_send(chat_id=chat_id, text=answer)

    return jsonify(ok=True)
