# app/routes/telegram.py
from __future__ import annotations

import os
import re
import logging
import requests
from flask import Blueprint, request, jsonify

from app.services.accounts_service import upsert_account, lookup_account
from app.core.supabase_client import supabase

bp = Blueprint("telegram", __name__)

TG_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TG_API = f"https://api.telegram.org/bot{TG_BOT_TOKEN}"

LINK_CODE_RE = re.compile(r"^[A-Z0-9]{8}$")


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


def _try_consume_link_code(provider_user_id: str, raw_text: str) -> dict:
    """
    Attempts to consume link token via RPC:
      consume_link_token(p_provider, p_code, p_provider_user_id)
    """
    code = (raw_text or "").strip().upper()
    if not LINK_CODE_RE.match(code):
        return {"ok": False, "reason": "not_a_code"}

    try:
        res = (
            supabase()
            .rpc(
                "consume_link_token",
                {
                    "p_provider": "tg",
                    "p_code": code,
                    "p_provider_user_id": provider_user_id,
                },
            )
            .execute()
        )
    except Exception as e:
        return {"ok": False, "reason": "rpc_error", "error": str(e)}

    row = (res.data or [None])[0]
    if not row:
        return {"ok": False, "reason": "no_rpc_row"}

    if row.get("ok") is True and row.get("auth_user_id"):
        return {"ok": True, "auth_user_id": row.get("auth_user_id")}

    return {"ok": False, "reason": row.get("reason") or "consume_failed", "rpc": row}


@bp.post("/telegram/webhook")
def tg_webhook():
    """
    Telegram sends updates here.

    Flow:
    1) Upsert account shell (provider=tg)
    2) If linked -> acknowledge
    3) If not linked:
       - if user sent 8-char code => consume_link_token() and link immediately
       - else instruct user to generate code on website
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

    if not tg_user_id:
        return jsonify({"ok": True, "ignored": True})

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

    # If already linked
    if lk.get("linked"):
        if text and text.lower().startswith("/start"):
            _tg_send(chat_id, "Welcome! Your Telegram is linked ✅. Send your question anytime.")
        elif text:
            _tg_send(chat_id, f"Received: {text}\n(Linked ✅)")
        else:
            _tg_send(chat_id, "Linked ✅")
        return jsonify({"ok": True, "linked": True})

    # Not linked: try consuming code if user sent one
    if text:
        attempt = _try_consume_link_code(tg_user_id, text)
        if attempt.get("ok"):
            _tg_send(chat_id, "✅ Telegram linked successfully!\nNow you can send your questions here anytime.")
            return jsonify({"ok": True, "linked": True, "linked_now": True})

    # Not linked and no valid code
    _tg_send(
        chat_id,
        "Your Telegram is not linked yet.\n"
        "1) Login on the website\n"
        "2) Generate your LINK CODE\n"
        "3) Reply here with the 8-character code\n\n"
        "Example: 7K9M2H8P",
    )
    return jsonify({"ok": True, "linked": False})
