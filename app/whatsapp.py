import os
import json
import logging
import requests
from typing import Optional, Tuple
from flask import Blueprint, request, jsonify

bp = Blueprint("whatsapp", __name__)

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")  # e.g. https://xxxx.koyeb.app

def _extract_inbound_message(payload: dict) -> Optional[Tuple[str, str]]:
    """
    Returns (wa_phone, text) or None
    """
    try:
        entry = payload.get("entry", [])[0]
        changes = entry.get("changes", [])[0]
        value = changes.get("value", {})
        messages = value.get("messages", [])
        if not messages:
            return None

        msg = messages[0]
        wa_phone = msg.get("from", "")
        msg_type = msg.get("type", "")

        # Only handle text for now
        if msg_type == "text":
            text = msg.get("text", {}).get("body", "").strip()
            if wa_phone and text:
                return wa_phone, text

        return None
    except Exception:
        return None

def _send_whatsapp_text(to_phone: str, text: str) -> None:
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        raise RuntimeError("WHATSAPP_TOKEN / WHATSAPP_PHONE_NUMBER_ID not set")

    url = f"https://graph.facebook.com/v24.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    body = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text[:3900]}  # keep safe size
    }
    r = requests.post(url, headers=headers, json=body, timeout=20)
    if r.status_code >= 300:
        raise RuntimeError(f"WhatsApp send failed {r.status_code}: {r.text}")

@bp.get("/whatsapp/webhook")
def whatsapp_webhook_verify():
    """
    Meta verification handshake:
    GET /whatsapp/webhook?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN and challenge:
        logging.info("WhatsApp webhook verified successfully.")
        return challenge, 200

    logging.warning("WhatsApp webhook verify failed.")
    return "forbidden", 403

@bp.post("/whatsapp/webhook")
def whatsapp_webhook_inbound():
    """
    Inbound messages from Meta. Must return 200 quickly.
    """
    payload = request.get_json(silent=True) or {}
    logging.info("WA_WEBHOOK_INBOUND payload=%s", json.dumps(payload)[:5000])

    extracted = _extract_inbound_message(payload)
    if not extracted:
        # statuses, delivery receipts, etc. still return ok
        return jsonify({"ok": True}), 200

    wa_phone, text = extracted

    # Basic commands
    if text.lower() in ("help", "hepl", "start", "hi"):
        reply = (
            "Welcome to Naija Tax Guide.\n"
            "Ask your tax question in one message.\n\n"
            "Example: What is VAT in Nigeria?"
        )
        try:
            _send_whatsapp_text(wa_phone, reply)
        except Exception as e:
            logging.exception("Failed to send help reply: %s", str(e))
        return jsonify({"ok": True}), 200

    # --- AI Reply (calls your own /ask endpoint) ---
    try:
        ask_url = f"{APP_BASE_URL}/ask" if APP_BASE_URL else None
        if not ask_url:
            raise RuntimeError("APP_BASE_URL not set (needed to call /ask)")

        r = requests.post(
            ask_url,
            headers={"Content-Type": "application/json"},
            json={"wa_phone": wa_phone, "question": text},
            timeout=60
        )
        if r.status_code >= 300:
            raise RuntimeError(f"/ask failed {r.status_code}: {r.text}")

        data = r.json()
        answer = data.get("answer", "") or "Sorry, I could not generate a response. Try again."

        _send_whatsapp_text(wa_phone, answer)

    except Exception as e:
        logging.exception("AI reply failed: %s", str(e))
        # fallback reply so user sees something
        try:
            _send_whatsapp_text(wa_phone, "Sorry—system is busy. Please try again in 1 minute.")
        except Exception:
            pass

    return jsonify({"ok": True}), 200
