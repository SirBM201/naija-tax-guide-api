# app/routes/telegram.py
from __future__ import annotations

import os
import re
import logging
import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.services.accounts_service import (
    upsert_account,
    lookup_account,
    upsert_account_link,
)

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


def _consume_link_code(provider: str, code: str, provider_user_id: str) -> dict:
    """
    Calls RPC: public.consume_link_token(p_provider text, p_code text, p_provider_user_id text)
    Expected return: a row with at least:
      ok boolean, auth_user_id uuid (when ok=true)
    """
    res = supabase().rpc(
        "consume_link_token",
        {
            "p_provider": provider,
            "p_code": code,
            "p_provider_user_id": provider_user_id,
        },
    ).execute()
    return (res.data or [None])[0] or {}


@bp.post("/telegram/webhook")
def tg_webhook():
    """
    Telegram sends updates here.
    Flow:
      1) Upsert "shell" account row for (tg, provider_user_id)
      2) If not linked:
           - If message is 8-char code: consume RPC + upsert auth_user_id link
           - Else: ask user to send code
      3) If linked: acknowledge (later you can forward to /ask)
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

    # If NOT linked, try to consume code (if user sent one)
    if not lk.get("linked"):
        candidate = (text or "").upper().strip()
        if candidate and LINK_CODE_RE.match(candidate):
            try:
                out = _consume_link_code("tg", candidate, tg_user_id)
                if out.get("ok") is True and out.get("auth_user_id"):
                    upsert_account_link(
                        provider="tg",
                        provider_user_id=tg_user_id,
                        auth_user_id=str(out.get("auth_user_id")),
                        display_name=display_name,
                        phone=None,
                    )
                    _tg_send(chat_id, "Linked ✅. You can now ask your question here anytime.")
                    return jsonify({"ok": True, "linked": True, "just_linked": True})

                _tg_send(
                    chat_id,
                    "Invalid or expired code.\n"
                    "Please login on the website and generate a NEW LINK CODE, then send it here.",
                )
                return jsonify({"ok": True, "linked": False})
            except Exception as e:
                logging.exception("TG consume_link_token failed: %s", e)
                _tg_send(chat_id, "System error while linking. Please try again.")
                return jsonify({"ok": True, "linked": False})

        _tg_send(
            chat_id,
            "Your Telegram is not linked yet.\n"
            "Please login on the website and generate your LINK CODE, then reply here with the 8-character code.\n"
            "Example: 7K9M2H8P",
        )
        return jsonify({"ok": True, "linked": False})

    # Linked path (later: forward to /ask)
    if text:
        if text.lower().startswith("/start"):
            _tg_send(chat_id, "Welcome! Your Telegram is linked ✅. Send your question anytime.")
        else:
            _tg_send(chat_id, f"Received: {text}\n(Linked ✅)")

    return jsonify({"ok": True, "linked": True})
