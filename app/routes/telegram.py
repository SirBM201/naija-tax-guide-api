# app/routes/telegram.py
from __future__ import annotations

import os
import re
import logging
import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.services.accounts_service import upsert_account, lookup_account, upsert_account_link

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


def _try_consume_link_code(provider: str, provider_user_id: str, code: str) -> dict:
    """
    Calls Supabase RPC: consume_link_token(p_provider, p_code, p_provider_user_id)
    """
    try:
        res = supabase().rpc(
            "consume_link_token",
            {
                "p_provider": provider,
                "p_code": code,
                "p_provider_user_id": provider_user_id,
            },
        ).execute()
    except Exception as e:
        return {"ok": False, "error": f"RPC error: {str(e)}"}

    row = (res.data or [None])[0]
    if not row:
        return {"ok": False, "error": "No RPC row returned."}

    ok = bool(row.get("ok"))
    auth_user_id = row.get("auth_user_id")
    return {"ok": ok, "auth_user_id": auth_user_id, "raw": row}


@bp.post("/telegram/webhook")
def tg_webhook():
    """
    Telegram sends updates here.

    Behavior:
    1) Upsert account shell
    2) If linked -> acknowledge
    3) If not linked:
       - If text is 8-char code -> consume_link_token RPC, then upsert_account_link
       - Else -> tell user how to link
    """
    update = request.get_json(silent=True) or {}
    msg = update.get("message") or update.get("edited_message") or {}
    if not msg:
        return jsonify({"ok": True, "ignored": True})

    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if chat_id is None:
        return jsonify({"ok": True, "ignored": True})

    text = (msg.get("text") or "").strip()

    user = msg.get("from") or {}
    tg_user_id = str(user.get("id") or "").strip()
    display_name = " ".join([x for x in [user.get("first_name"), user.get("last_name")] if x]) or None

    try:
        # 1) create/update account shell
        upsert_account(
            provider="tg",
            provider_user_id=tg_user_id,
            display_name=display_name,
            phone=None,
        )

        # 2) lookup link status
        lk = lookup_account(provider="tg", provider_user_id=tg_user_id)
        if not lk.get("ok"):
            _tg_send(chat_id, "System error. Please try again.")
            return jsonify({"ok": True})

        if lk.get("linked"):
            if text.lower().startswith("/start"):
                _tg_send(chat_id, "Welcome! Your Telegram is linked ✅. Send your question anytime.")
            elif text:
                _tg_send(chat_id, f"Received: {text}\n(Linked ✅)")
            else:
                _tg_send(chat_id, "Linked ✅")
            return jsonify({"ok": True, "linked": True})

        # 3) Not linked -> if user sent code, try to link
        code = (text or "").strip().upper()
        if code and LINK_CODE_RE.match(code):
            consume = _try_consume_link_code("tg", tg_user_id, code)
            if consume.get("ok") and consume.get("auth_user_id"):
                auth_user_id = str(consume["auth_user_id"])

                link_res = upsert_account_link(
                    provider="tg",
                    provider_user_id=tg_user_id,
                    auth_user_id=auth_user_id,
                    display_name=display_name,
                    phone=None,
                )
                if link_res.get("ok"):
                    _tg_send(chat_id, "✅ Linked successfully!\nYou can now send your questions here anytime.")
                    return jsonify({"ok": True, "linked": True})

                _tg_send(chat_id, "Link succeeded but saving failed. Please try again.")
                return jsonify({"ok": True, "linked": False})

            _tg_send(
                chat_id,
                "❌ Invalid or expired LINK CODE.\n"
                "Please login on the website and generate a NEW LINK CODE, then send it here.\n"
                "Example: 7K9M2H8P",
            )
            return jsonify({"ok": True, "linked": False})

        # Otherwise: instruct linking
        _tg_send(
            chat_id,
            "Your Telegram is not linked yet.\n"
            "Please login on the website and generate your LINK CODE, then reply here with the 8-character code.\n"
            "Example: 7K9M2H8P",
        )
        return jsonify({"ok": True, "linked": False})

    except Exception as e:
        logging.exception("TG webhook error: %s", e)
        _tg_send(chat_id, "System error. Please try again.")
        return jsonify({"ok": True})
