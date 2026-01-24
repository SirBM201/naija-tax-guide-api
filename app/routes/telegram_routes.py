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

@bp.post("/telegram/webhook/<secret>")
def telegram_webhook(secret: str):
    # Secret check (this is what triggers 401 if mismatch)
    expected = (TELEGRAM_WEBHOOK_SECRET or "").strip()
    if not expected or secret != expected:
        log.warning("Telegram webhook secret mismatch. got=%s expected=%s", secret, expected)
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    update = request.get_json(silent=True) or {}
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()

    log.info("TG chat_id=%s msg=%s", chat_id, text)

    # Always return 200 quickly if message is not usable
    if not chat_id or not text:
        return jsonify({"ok": True, "sent": False}), 200

    # Use chat_id as identity for now (same as you’re doing already)
    res = resolve_answer(wa_phone=str(chat_id), question=text, lang="en", source="telegram")
    answer_text = res.get("answer_text") or "I can help. Ask a tax question."

    sent = tg_send_message(int(chat_id), answer_text)

    return jsonify({"ok": True, "sent": sent}), 200
