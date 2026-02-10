# app/routes/whatsapp.py
from __future__ import annotations

import os
import re
import logging
import requests
from flask import Blueprint, request, jsonify

from app.services.accounts_service import upsert_account, lookup_account
from app.core.supabase_client import supabase

bp = Blueprint("whatsapp", __name__)

WA_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WA_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()

API_BASE = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"

LINK_CODE_RE = re.compile(r"^[A-Z0-9]{8}$")


def _wa_send_text(to_phone: str, text: str) -> None:
    if not (WA_ACCESS_TOKEN and WA_PHONE_NUMBER_ID):
        logging.warning("WhatsApp env not set (WHATSAPP_ACCESS_TOKEN/WHATSAPP_PHONE_NUMBER_ID)")
        return

    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"preview_url": False, "body": text},
    }
    headers = {
        "Authorization": f"Bearer {WA_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
        r = requests.post(API_BASE, json=payload, headers=headers, timeout=15)
        if r.status_code >= 300:
            logging.warning("WA send failed: %s %s", r.status_code, r.text)
    except Exception as e:
        logging.exception("WA send exception: %s", e)


def _extract_message(body: dict) -> tuple[str, str]:
    """
    Returns (from_phone, text). If no message, returns ("","").
    """
    entry = (body.get("entry") or [None])[0] or {}
    changes = (entry.get("changes") or [None])[0] or {}
    value = changes.get("value") or {}
    messages = value.get("messages") or []
    if not messages:
        return "", ""

    msg = messages[0]
    from_phone = (msg.get("from") or "").strip()

    msg_type = msg.get("type")
    text = ""
    if msg_type == "text":
        text = ((msg.get("text") or {}).get("body") or "").strip()

    return from_phone, text


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
                    "p_provider": "wa",
                    "p_code": code,
                    "p_provider_user_id": provider_user_id,
                },
            )
            .execute()
        )
    except Exception as e:
        return {"ok": False, "reason": "rpc_error", "error": str(e)}

    row = (res.data or [None])[0]
    # expected fields: ok, auth_user_id, message? etc
    if not row:
        return {"ok": False, "reason": "no_rpc_row"}

    if row.get("ok") is True and row.get("auth_user_id"):
        return {"ok": True, "auth_user_id": row.get("auth_user_id")}

    return {"ok": False, "reason": row.get("reason") or "consume_failed", "rpc": row}


@bp.get("/whatsapp/webhook")
def wa_webhook_verify():
    """
    Meta webhook verification:
    GET ?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    """
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token and WA_VERIFY_TOKEN and token == WA_VERIFY_TOKEN:
        return (challenge or ""), 200
    return "Forbidden", 403


@bp.post("/whatsapp/webhook")
def wa_webhook_receive():
    """
    Receives WhatsApp messages.

    Flow:
    1) Upsert account shell (provider=wa)
    2) If linked -> acknowledge
    3) If not linked:
       - if user sent 8-char code => consume_link_token() and link immediately
       - else instruct user to generate code on website
    """
    body = request.get_json(silent=True) or {}

    try:
        from_phone, text = _extract_message(body)
        if not from_phone:
            return jsonify({"ok": True, "ignored": True})

        # create/update account shell
        upsert_account(
            provider="wa",
            provider_user_id=from_phone,
            display_name=None,
            phone=from_phone,
        )

        lk = lookup_account(provider="wa", provider_user_id=from_phone)
        if not lk.get("ok"):
            _wa_send_text(from_phone, "System error. Please try again.")
            return jsonify({"ok": True})

        # If already linked
        if lk.get("linked"):
            if text:
                _wa_send_text(from_phone, f"Received: {text}\n(Linked ✅)")
            else:
                _wa_send_text(from_phone, "Linked ✅")
            return jsonify({"ok": True, "linked": True})

        # Not linked yet: try consuming code if user sent one
        if text:
            attempt = _try_consume_link_code(from_phone, text)
            if attempt.get("ok"):
                _wa_send_text(
                    from_phone,
                    "✅ WhatsApp linked successfully!\nNow you can send your questions here anytime.",
                )
                return jsonify({"ok": True, "linked": True, "linked_now": True})

        # Not linked and no valid code provided
        _wa_send_text(
            from_phone,
            "Your WhatsApp is not linked yet.\n"
            "1) Login on the website\n"
            "2) Generate your LINK CODE\n"
            "3) Reply here with the 8-character code\n\n"
            "Example: 7K9M2H8P",
        )
        return jsonify({"ok": True, "linked": False})

    except Exception as e:
        logging.exception("WA webhook error: %s", e)
        # don't make Meta retry forever
        return jsonify({"ok": True})
