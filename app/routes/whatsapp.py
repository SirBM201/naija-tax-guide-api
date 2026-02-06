from __future__ import annotations

import os
import logging
import requests
from flask import Blueprint, request, jsonify

from app.services.channel_linking_service import extract_code, consume_and_link

bp = Blueprint("whatsapp", __name__)

# Meta verify token (you provided)
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify").strip()

# WhatsApp Cloud API send-message
WHATSAPP_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()


def _wa_send_text(to: str, text: str) -> None:
    if not WHATSAPP_ACCESS_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        logging.warning("WHATSAPP_ACCESS_TOKEN / WHATSAPP_PHONE_NUMBER_ID not set; cannot send reply")
        return

    url = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": text},
    }

    try:
        requests.post(url, headers=headers, json=payload, timeout=10)
    except Exception as e:
        logging.warning("Failed to send WA message: %s", e)


@bp.get("/whatsapp/webhook")
def whatsapp_verify():
    """
    Meta verification:
      hub.mode=subscribe
      hub.verify_token=<your token>
      hub.challenge=<challenge>
    """
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
    If message contains a link-code -> consumes + links -> replies.
    Always returns 200 to Meta quickly.
    """
    payload = request.get_json(silent=True) or {}

    try:
        entry = (payload.get("entry") or [None])[0] or {}
        changes = (entry.get("changes") or [None])[0] or {}
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            return jsonify({"ok": True})

        msg = messages[0]
        from_id = (msg.get("from") or "").strip()  # WhatsApp user id (phone number format)
        mtype = (msg.get("type") or "").strip()

        text = ""
        if mtype == "text":
            text = ((msg.get("text") or {}).get("body") or "").strip()

        # Optional contact name
        contacts = value.get("contacts") or []
        display_name = None
        if contacts:
            profile = (contacts[0].get("profile") or {})
            display_name = (profile.get("name") or "").strip() or None

        # ACK fast if no sender or no text
        if not from_id or not text:
            return jsonify({"ok": True})

        code = extract_code(text)
        if not code:
            # If they wrote "start" or "link", guide them (one-liner)
            low = text.lower()
            if "link" in low or "code" in low or "start" in low:
                _wa_send_text(
                    from_id,
                    "To link your WhatsApp, send your 6–12 character code here.\nExample: ABC12345",
                )
            return jsonify({"ok": True})

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
            _wa_send_text(
                from_id,
                "❌ Link failed.\nYour code is invalid or expired. Please generate a new code and try again.",
            )

        return jsonify({"ok": True})

    except Exception as e:
        logging.exception("WA webhook error: %s", e)
        # Still return 200 to avoid retries storm
        return jsonify({"ok": True})
