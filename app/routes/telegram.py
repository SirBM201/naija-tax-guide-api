# app/routes/telegram.py
from __future__ import annotations

import os
import logging
import requests
from flask import Blueprint, request, jsonify

from app.services.accounts_service import upsert_account, lookup_account

bp = Blueprint("telegram", __name__)

TG_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TG_API = f"https://api.telegram.org/bot{TG_BOT_TOKEN}"


def _tg_send(chat_id: int, text: str) -> None:
    if not TG_BOT_TOKEN:
        logging.warning("Telegram env not set (TELEGRAM_BOT_TOKEN)")
        return
    try:
        r = requests.post(
            f"{TG_API}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=15,
        )
        if r.status_code >= 300:
            logging.warning("TG send failed: %s %s", r.status_code, r.text)
    except Exception as e:
        logging.exception("TG send exception: %s", e)


@bp.post("/telegram/webhook")
def tg_webhook():
    """
    Telegram sends updates here.
    """
    update = request.get_json(silent=True) or {}
    msg = update.get("message") or update.get("edited_message") or {}
    if not msg:
        return jsonify({"ok": True, "ignored": True})

    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text = (msg.get("text") or "").strip()

    user = msg.get("from") or {}
    tg_user_id = str(user.get("id") or "").strip()
    display_name = " ".join([x for x in [user.get("first_name"), user.get("last_name")] if x]) or None

    # create/update account shell
    upsert_account(
        provider="tg",
        provider_user_id=tg_user_id,
        display_name=display_name,
        phone=None,
    )

    lk = lookup_account(provider="tg", provider_user_id=tg_user_id)
    if not lk.get("ok"):
        _tg_send(chat_id, "System error. Please try again.")
        return jsonify({"ok": True})

    if not lk.get("linked"):
        _tg_send(
            chat_id,
            "Your Telegram is not linked yet.\n"
            "Please login on the website and generate your LINK CODE, then reply here with the 8-character code.\n"
            "Example: 7K9M2H8P",
        )
        return jsonify({"ok": True, "linked": False})

    if text:
        if text.lower().startswith("/start"):
            _tg_send(chat_id, "Welcome! Your Telegram is linked ✅. Send your question anytime.")
        else:
            _tg_send(chat_id, f"Received: {text}\n(Linked ✅)")

    return jsonify({"ok": True, "linked": True})
