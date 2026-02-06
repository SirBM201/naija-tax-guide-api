# app/routes/whatsapp.py
from __future__ import annotations

import os
import logging
import requests
from flask import Blueprint, request, jsonify

from app.services.accounts_service import upsert_account, lookup_account

bp = Blueprint("whatsapp", __name__)

WA_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WA_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()

API_BASE = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"


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
    - creates/updates account shell
    - if not linked, asks user to link by sending the 8-char code
    - if linked, you can forward to your /ask endpoint later
    """
    body = request.get_json(silent=True) or {}

    try:
        entry = (body.get("entry") or [None])[0] or {}
        changes = (entry.get("changes") or [None])[0] or {}
        value = changes.get("value") or {}
        messages = value.get("messages") or []
        if not messages:
            return jsonify({"ok": True, "ignored": True})

        msg = messages[0]
        from_phone = (msg.get("from") or "").strip()  # sender WA id (phone)
        msg_type = msg.get("type")
        text = ""
        if msg_type == "text":
            text = ((msg.get("text") or {}).get("body") or "").strip()

        # create/update account shell
        upsert_account(
            provider="wa",
            provider_user_id=from_phone,
            display_name=None,
            phone=from_phone,
        )

        # lookup link status
        lk = lookup_account(provider="wa", provider_user_id=from_phone)
        if not lk.get("ok"):
            _wa_send_text(from_phone, "System error. Please try again.")
            return jsonify({"ok": True})

        if not lk.get("linked"):
            _wa_send_text(
                from_phone,
                "Your WhatsApp is not linked yet.\n"
                "Please login on the website and generate your LINK CODE, then reply here with the 8-character code.\n"
                "Example: 7K9M2H8P",
            )
            return jsonify({"ok": True, "linked": False})

        # If user sends a code, you can call /api/link-tokens/consume from frontend.
        # For now, just acknowledge (you can wire /ask later).
        if text:
            _wa_send_text(from_phone, f"Received: {text}\n(Linked ✅)")

        return jsonify({"ok": True, "linked": True})

    except Exception as e:
        logging.exception("WA webhook error: %s", e)
        return jsonify({"ok": True})  # don't make Meta retry forever
