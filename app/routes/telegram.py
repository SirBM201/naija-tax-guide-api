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

CODE_RE = re.compile(r"^[A-Z0-9]{8}$", re.IGNORECASE)


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


def _try_link_with_code(provider_user_id: str, code: str) -> dict:
    """
    Uses Supabase RPC consume_link_token(p_provider, p_code, p_provider_user_id).
    If ok, binds auth_user_id to accounts table.
    """
    try:
        resp = (
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
        return {"ok": False, "error": f"RPC error: {str(e)}"}

    row = (resp.data or [None])[0] if isinstance(resp.data, list) else resp.data
    if not row or not row.get("ok"):
        return {"ok": False, "reason": "invalid_or_expired_code"}

    auth_user_id = (row.get("auth_user_id") or "").strip()
    if not auth_user_id:
        return {"ok": False, "reason": "no_auth_user_returned"}

    linked = upsert_account_link(
        provider="tg",
        provider_user_id=provider_user_id,
        auth_user_id=auth_user_id,
        display_name=None,
        phone=None,
    )
    if not linked.get("ok"):
        return {"ok": False, "error": linked.get("error") or "Failed to link account"}

    return {"ok": True, "auth_user_id": auth_user_id}


@bp.post("/telegram/webhook")
def tg_webhook():
    """
    Telegram sends updates here.
    - upsert account shell
    - if not linked: ask for link code
    - if user sends 8-char code: consume_link_token RPC and link immediately
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

    # Create/update account shell
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

    # Not linked yet
    if not lk.get("linked"):
        if text and CODE_RE.match(text.strip()):
            res = _try_link_with_code(tg_user_id, text.strip().upper())
            if res.get("ok"):
                _tg_send(chat_id, "✅ Linked successfully.\nYou can now send your questions anytime.")
                return jsonify({"ok": True, "linked": True})

            _tg_send(
                chat_id,
                "❌ Invalid/expired code.\n"
                "Please login on the website, generate a NEW LINK CODE, then reply here with the 8-character code.\n"
                "Example: 7K9M2H8P",
            )
            return jsonify({"ok": True, "linked": False})

        _tg_send(
            chat_id,
            "Your Telegram is not linked yet.\n"
            "Please login on the website and generate your LINK CODE, then reply here with the 8-character code.\n"
            "Example: 7K9M2H8P",
        )
        return jsonify({"ok": True, "linked": False})

    # Linked user
    if text:
        if text.lower().startswith("/start"):
            _tg_send(chat_id, "Welcome! Your Telegram is linked ✅. Send your question anytime.")
        else:
            _tg_send(chat_id, f"Received: {text}\n(Linked ✅)")

    return jsonify({"ok": True, "linked": True})
