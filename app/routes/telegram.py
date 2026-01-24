# app/routes/telegram.py
import hmac
import logging
from typing import Optional

import requests
from flask import Blueprint, request, jsonify

from app.core.config import TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_SECRET
from app.services.engine import resolve_answer

bp = Blueprint("telegram", __name__, url_prefix="/telegram")


def _eq(a: str, b: str) -> bool:
    a = (a or "").strip()
    b = (b or "").strip()
    return bool(a) and bool(b) and hmac.compare_digest(a, b)


def _get_text(update: dict) -> tuple[Optional[int], Optional[str]]:
    """
    Supports:
      - message.text
      - edited_message.text
    """
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text = msg.get("text")
    if not chat_id or not text:
        return None, None
    return int(chat_id), str(text)


def _send_message(chat_id: int, text: str) -> None:
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN not set")

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    r = requests.post(url, json=payload, timeout=20)
    r.raise_for_status()


@bp.get("/health")
def health():
    return jsonify({"ok": True, "service": "telegram"}), 200


@bp.post("/webhook")
@bp.post("/webhook/<path_secret>")
def webhook(path_secret: Optional[str] = None):
    """
    Security:
    - If TELEGRAM_WEBHOOK_SECRET is set, we accept EITHER:
      A) secret in the URL path (/webhook/<secret>)
      OR
      B) Telegram header 'X-Telegram-Bot-Api-Secret-Token' (secret_token feature)

    If TELEGRAM_WEBHOOK_SECRET is empty, we allow requests (not recommended).
    """
    expected = (TELEGRAM_WEBHOOK_SECRET or "").strip()
    got_header = (request.headers.get("X-Telegram-Bot-Api-Secret-Token", "") or "").strip()
    got_path = (path_secret or "").strip()

    if expected:
        ok = _eq(got_path, expected) or _eq(got_header, expected)
        if not ok:
            logging.warning(
                "Telegram webhook secret mismatch. got_path=%s got_header=%s expected=%s",
                got_path[:12] + "..." if got_path else "",
                got_header[:12] + "..." if got_header else "",
                expected[:12] + "..."
            )
            return jsonify({"ok": False, "error": "unauthorized"}), 401

    update = request.get_json(silent=True) or {}
    chat_id, text = _get_text(update)

    logging.info("TG inbound chat_id=%s text=%s", chat_id, (text or "")[:200])

    # Telegram may send non-text updates (stickers, joins, etc.)
    if not chat_id or not text:
        return jsonify({"ok": True, "ignored": True}), 200

    res = resolve_answer(
        wa_phone=f"tg:{chat_id}",
        question=text,
        mode="text",
        lang="en",
        source="telegram",
    )

    answer = (res.get("answer_text") or "").strip() or "Please ask your tax question."
    try:
        _send_message(chat_id, answer)
    except Exception as e:
        logging.exception("TG send failed: %s", e)
        return jsonify({"ok": False, "error": "send_failed"}), 500

    return jsonify({"ok": True}), 200
