import logging
import requests
from flask import Blueprint, request, jsonify

from app.core.config import TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_SECRET
from app.services.engine import resolve_answer

bp = Blueprint("telegram", __name__)
log = logging.getLogger(__name__)

def tg_send_message(chat_id: int, text: str) -> bool:
    if not TELEGRAM_BOT_TOKEN:
        log.error("TELEGRAM_BOT_TOKEN not set")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}

    try:
        r = requests.post(url, json=payload, timeout=15)
        ok = (r.status_code == 200 and (r.json() or {}).get("ok") is True)
        if not ok:
            log.error("Telegram sendMessage failed: status=%s body=%s", r.status_code, r.text[:500])
        return ok
    except Exception as e:
        log.exception("Telegram sendMessage exception: %s", e)
        return False

def _expected_secret() -> str:
    # Normalize to avoid invisible whitespace issues from env
    return (TELEGRAM_WEBHOOK_SECRET or "").strip().replace("\r", "").replace("\n", "")

@bp.post("/telegram/webhook")
def telegram_webhook():
    """
    Durable webhook security:
    - Telegram setWebhook supports secret_token
    - Telegram will send header: X-Telegram-Bot-Api-Secret-Token
    - We validate that header against TELEGRAM_WEBHOOK_SECRET
    """
    expected = _expected_secret()
    provided = (request.headers.get("X-Telegram-Bot-Api-Secret-Token") or "").strip()
    provided = provided.replace("\r", "").replace("\n", "")

    if not expected:
        log.error("TELEGRAM_WEBHOOK_SECRET not set (cannot validate Telegram)")
        return jsonify({"ok": False, "error": "server_misconfigured"}), 500

    if provided != expected:
        log.warning("Telegram secret header mismatch. provided=%r expected=%r", provided, expected)
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    update = request.get_json(silent=True) or {}
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()

    log.info("TG inbound chat_id=%s text=%s", chat_id, text[:200])

    if not chat_id or not text:
        return jsonify({"ok": True, "sent": False}), 200

    res = resolve_answer(
        wa_phone=str(chat_id),
        question=text,
        mode="text",
        lang="en",
        source="telegram",
    )
    answer_text = res.get("answer_text") or "I can help. Ask a tax question (e.g., VAT, PAYE, TIN)."

    sent = tg_send_message(int(chat_id), answer_text)
    return jsonify({"ok": True, "sent": sent}), 200
