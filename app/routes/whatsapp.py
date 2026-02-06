# app/routes/whatsapp.py

from __future__ import annotations

import os
import logging
import requests
from flask import Blueprint, request, jsonify

from app.services.channel_linking_service import extract_code, consume_and_link

bp = Blueprint("whatsapp", __name__)

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify").strip()
WHATSAPP_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()


def _wa_send_text(to: str, text: str):
    if not WHATSAPP_ACCESS_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        logging.warning("WA credentials missing")
        return

    url = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"

    headers = {
        "Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": text}
    }

    requests.post(url, headers=headers, json=payload)


# VERIFY
@bp.get("/whatsapp/webhook")
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200

    return jsonify({"ok": False}), 403


# RECEIVE
@bp.post("/whatsapp/webhook")
def webhook():

    payload = request.get_json(silent=True) or {}

    try:
        entry = payload["entry"][0]
        changes = entry["changes"][0]
        value = changes["value"]

        msg = value["messages"][0]
        from_id = msg["from"]

        text = ""
        if msg["type"] == "text":
            text = msg["text"]["body"]

        code = extract_code(text)

        if not code:
            _wa_send_text(
                from_id,
                "Send your linking code.\nExample: ABC23456"
            )
            return jsonify({"ok": True})

        result = consume_and_link(
            provider="wa",
            code=code,
            provider_user_id=from_id,
            display_name=None,
            phone=from_id
        )

        if result["ok"]:
            _wa_send_text(from_id, "✅ WhatsApp linked successfully.")
        else:
            _wa_send_text(from_id, "❌ Invalid or expired code.")

    except Exception as e:
        logging.exception(e)

    return jsonify({"ok": True})
