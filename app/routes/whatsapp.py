from flask import Blueprint, request, jsonify
import os
import re
import requests

bp = Blueprint("whatsapp", __name__)

# WhatsApp Cloud API
WA_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()

# Meta verify token (set same value in Meta dashboard + env)
WA_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()

# Your public API base URL (Koyeb)
PUBLIC_API_BASE_URL = os.getenv(
    "PUBLIC_API_BASE_URL",
    "https://incredible-nonie-bmsconcept-37359733.koyeb.app"
).strip()

CODE_RE = re.compile(r"(?:^|\b)([A-Z0-9]{6,12})(?:\b|$)", re.I)

def _wa_send_text(to_wa_id: str, text: str) -> None:
    """
    Send text message via WhatsApp Cloud API.
    """
    if not WA_TOKEN or not WA_PHONE_NUMBER_ID:
        return

    url = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WA_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_id,
        "type": "text",
        "text": {"body": text},
    }

    try:
        requests.post(url, headers=headers, json=payload, timeout=15)
    except Exception:
        pass

def _extract_incoming_message(payload: dict):
    """
    Returns (wa_id, text) or (None, None)
    """
    try:
        entry = payload.get("entry", [])[0]
        change = entry.get("changes", [])[0]
        value = change.get("value", {})
        msgs = value.get("messages") or []
        if not msgs:
            return None, None
        msg = msgs[0]
        wa_id = msg.get("from")
        text = (msg.get("text") or {}).get("body") or ""
        return wa_id, text
    except Exception:
        return None, None

def _extract_code(text: str) -> str | None:
    """
    Accepts:
      - LINK ABCD1234
      - ABCD1234
    """
    if not text:
        return None
    t = text.strip().upper()

    if t.startswith("LINK "):
        candidate = t.replace("LINK", "", 1).strip()
        return candidate if candidate else None

    # If short message, allow bare code
    m = CODE_RE.search(t)
    if m and len(t.split()) <= 3:
        return m.group(1).upper()

    return None

@bp.get("/whatsapp/webhook")
def whatsapp_verify():
    """
    Meta webhook verification:
      GET ?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and WA_VERIFY_TOKEN and token == WA_VERIFY_TOKEN:
        # Must return the challenge as plain text
        return challenge, 200

    return jsonify({"ok": False, "error": "Verification failed"}), 403

@bp.post("/whatsapp/webhook")
def whatsapp_webhook():
    """
    Receives WA messages. If user sends LINK CODE, consumes link token.
    Always ACK with 200 quickly.
    """
    data = request.get_json(silent=True) or {}
    wa_id, text = _extract_incoming_message(data)

    # Always ACK
    if not wa_id:
        return jsonify({"ok": True})

    code = _extract_code(text)
    if not code:
        # Optional: help message
        # _wa_send_text(wa_id, "Send: LINK <CODE> to connect your account.")
        return jsonify({"ok": True})

    # Consume code via your backend API
    try:
        resp = requests.post(
            f"{PUBLIC_API_BASE_URL}/api/link-tokens/consume",
            json={
                "provider": "wa",
                "code": code,
                "provider_user_id": wa_id
            },
            timeout=15
        )
        j = resp.json()
    except Exception:
        _wa_send_text(wa_id, "⚠️ Network error. Please try again.")
        return jsonify({"ok": True})

    if j.get("ok"):
        _wa_send_text(wa_id, "✅ Linked successfully! Your WhatsApp is now connected.")
    else:
        _wa_send_text(wa_id, "❌ Invalid or expired code. Please request a new code and try again.")

    return jsonify({"ok": True})
