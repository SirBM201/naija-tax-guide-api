# app/routes/telegram.py
from __future__ import annotations

import os
import re
import logging
from flask import Blueprint, request, jsonify

from app.services.accounts_service import upsert_account, lookup_account
from app.core.supabase_client import supabase
from app.services.ask_service import ask_guarded
from app.services.outbound_service import send_telegram_text

bp = Blueprint("telegram", __name__)

LINK_CODE_RE = re.compile(r"^[A-Z0-9]{8}$")


def _try_consume_link_code(provider_user_id: str, raw_text: str) -> dict:
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
    Flow:
    - Upsert shell account (provider=tg)
    - If not linked: accept 8-char code and link OR instruct
    - If linked: treat message as a question -> ask_guarded -> send answer
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

    if not tg_user_id or not chat_id:
        return jsonify({"ok": True, "ignored": True})

    # ensure account exists
    upsert_account(provider="tg", provider_user_id=tg_user_id, display_name=display_name, phone=None)

    lk = lookup_account(provider="tg", provider_user_id=tg_user_id)
    if not lk.get("ok"):
        send_telegram_text(chat_id, "System error. Please try again.")
        return jsonify({"ok": True})

    # Not linked yet -> try code
    if not lk.get("linked"):
        if text:
            attempt = _try_consume_link_code(tg_user_id, text)
            if attempt.get("ok"):
                send_telegram_text(chat_id, "✅ Telegram linked successfully!\nNow send your tax question here anytime.")
                return jsonify({"ok": True, "linked": True, "linked_now": True})

        send_telegram_text(
            chat_id,
            "Your Telegram is not linked yet.\n"
            "1) Login on the website\n"
            "2) Generate your LINK CODE\n"
            "3) Reply here with the 8-character code\n\n"
            "Example: 7K9M2H8P",
        )
        return jsonify({"ok": True, "linked": False})

    # Linked -> answer questions
    if not text:
        send_telegram_text(chat_id, "Send your question as text and I will reply.")
        return jsonify({"ok": True, "linked": True, "ignored": True, "reason": "no_text"})

    # Optional: handle /start
    if text.lower().startswith("/start"):
        send_telegram_text(chat_id, "Welcome! Your Telegram is linked ✅. Send your tax question anytime.")
        return jsonify({"ok": True, "linked": True})

    resp = ask_guarded(
        {
            "provider": "tg",
            "provider_user_id": tg_user_id,
            "question": text,
            "lang": "en",
            "mode": "text",
        }
    )

    answer = (resp.get("answer") or resp.get("message") or "").strip()
    if not answer:
        answer = "I couldn't process that right now. Please try again."

    send_telegram_text(chat_id, answer)
    return jsonify({"ok": True, "linked": True, "ask": resp})
