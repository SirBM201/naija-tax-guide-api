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
        r = requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=10)
        if r.status_code >= 400:
            logging.warning("TG send failed %s: %s", r.status_code, r.text[:300])
    except Exception as e:
        logging.warning("Failed to send TG message: %s", e)


@bp.post("/telegram/webhook")
def telegram_webhook():
    payload = request.get_json(silent=True) or {}

    try:
        msg = payload.get("message") or payload.get("edited_message") or {}
        text = (msg.get("text") or "").strip()

        chat = msg.get("chat") or {}
        chat_id = chat.get("id")

        from_user = msg.get("from") or {}
        tg_user_id = from_user.get("id")  # numeric
        first = (from_user.get("first_name") or "").strip()
        last = (from_user.get("last_name") or "").strip()
        display_name = " ".join([p for p in (first, last) if p]).strip() or None
        username = (from_user.get("username") or "").strip() or None

        # Always ACK 200 to Telegram
        if not chat_id or not tg_user_id:
            return jsonify({"ok": True})

        code = extract_code(text)

        if not code:
            low = text.lower()
            if low.startswith("/start") or "link" in low or "code" in low:
                _tg_send(
                    chat_id,
                    "Welcome 👋\n\n"
                    "To link Telegram, send your 8-character code.\n"
                    "Example: 7K9M2XQH\n\n"
                    "You can also do:\n"
                    "/start 7K9M2XQH",
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
            _tg_send(chat_id, "✅ Linked successfully!\nYour Telegram is now connected.")
            return jsonify({"ok": True})

        reason = (result.get("reason") or "").strip()
        err = (result.get("error") or "").strip()

        if reason == "channel_already_linked":
            _tg_send(
                chat_id,
                "⚠️ This Telegram account is already linked to another user.\n"
                "If this is yours, ask admin to unlink it, then try again.",
            )
        elif err in ("invalid_or_expired_code", "invalid_code", "expired"):
            _tg_send(chat_id, "❌ Link failed.\nInvalid/expired code.\nGenerate a new code and try again.")
        else:
            _tg_send(chat_id, "❌ Link failed.\nGenerate a new code and try again.")

        return jsonify({"ok": True})

    except Exception as e:
        logging.exception("TG webhook error: %s", e)
        return jsonify({"ok": True})
