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


def _wa_send_text(to: str, text: str) -> None:
    if not WHATSAPP_ACCESS_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        logging.warning("WHATSAPP_ACCESS_TOKEN / WHATSAPP_PHONE_NUMBER_ID not set; cannot send reply")
        return

    url = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}", "Content-Type": "application/json"}
    payload = {"messaging_product": "whatsapp", "to": to, "type": "text", "text": {"body": text}}

    try:
        requests.post(url, headers=headers, json=payload, timeout=10)
    except Exception as e:
        logging.warning("Failed to send WA message: %s", e)


@bp.get("/whatsapp/webhook")
def whatsapp_verify():
    mode = (request.args.get("hub.mode") or "").strip()
    token = (request.args.get("hub.verify_token") or "").strip()
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN and challenge is not None:
        return str(challenge), 200

    return jsonify({"ok": False, "error": "Verification failed"}), 403


@bp.post("/whatsapp/webhook")
def whatsapp_webhook():
    """
    Receives inbound WA messages.
    - Extracts link code (6-12 chars) from text
    - Consumes + links
    - Replies to user
    Always ACKs 200 to Meta to prevent retry storms.
    """
    payload = request.get_json(silent=True) or {}

    try:
        entry = (payload.get("entry") or [None])[0] or {}
        changes = (entry.get("changes") or [None])[0] or {}
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            return jsonify({"ok": True})

        # Optional contact name
        contacts = value.get("contacts") or []
        display_name = None
        if contacts:
            profile = (contacts[0].get("profile") or {})
            display_name = (profile.get("name") or "").strip() or None

        # Process all messages (Meta can batch)
        for msg in messages:
            from_id = (msg.get("from") or "").strip()
            mtype = (msg.get("type") or "").strip()

            if not from_id:
                continue

            text = ""
            if mtype == "text":
                text = ((msg.get("text") or {}).get("body") or "").strip()

            if not text:
                continue

            code = extract_code(text)
            if not code:
                low = text.lower()
                if "link" in low or "code" in low or "start" in low:
                    _wa_send_text(
                        from_id,
                        "To link your WhatsApp, send your 6–12 character code here.\nExample: ABC12345",
                    )
                continue

            result = consume_and_link(
                provider="wa",
                code=code,
                provider_user_id=from_id,
                display_name=display_name,
                phone=from_id,
            )

            if result.get("ok"):
                _wa_send_text(
                    from_id,
                    "✅ Linked successfully!\nYour WhatsApp is now connected to your Naija Tax Guide account.",
                )
            else:
                err = (result.get("error") or "").strip()
                reason = (result.get("reason") or "").strip()

                if err == "rate_limited":
                    _wa_send_text(from_id, "⏳ Too many attempts. Please wait a minute and try again.")
                elif reason == "channel_already_linked":
                    _wa_send_text(from_id, "⚠️ This WhatsApp number is already linked to another account.")
                else:
                    _wa_send_text(
                        from_id,
                        "❌ Link failed.\nInvalid/expired code OR already used.\nGenerate a new code and try again.",
                    )

        return jsonify({"ok": True})

    except Exception as e:
        logging.exception("WA webhook error: %s", e)
        return jsonify({"ok": True})
