import os
import requests
from flask import Blueprint, request, jsonify, current_app

from app.subscriptions.service import mark_expired_if_needed

whatsapp_bp = Blueprint("whatsapp_bp", __name__, url_prefix="/whatsapp")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")

if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID or not WHATSAPP_VERIFY_TOKEN:
    raise RuntimeError("Missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID or WHATSAPP_VERIFY_TOKEN")

GRAPH_URL = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"


def send_whatsapp_text(to_phone: str, text: str):
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text},
    }
    r = requests.post(GRAPH_URL, headers=headers, json=payload, timeout=30)
    return r.status_code, r.text


def _get_text_message(payload: dict):
    """
    Extract sender and message text from WhatsApp webhook payload.
    """
    try:
        entry = payload["entry"][0]
        changes = entry["changes"][0]
        value = changes["value"]
        messages = value.get("messages", [])
        if not messages:
            return None, None
        msg = messages[0]
        from_phone = msg.get("from")
        text = (msg.get("text", {}) or {}).get("body", "")
        return from_phone, text
    except Exception:
        return None, None


@whatsapp_bp.get("/webhook")
def verify_webhook():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200
    return "Forbidden", 403


@whatsapp_bp.post("/webhook")
def receive_webhook():
    supabase = current_app.config["SUPABASE"]
    payload = request.get_json(silent=True) or {}

    from_phone, text = _get_text_message(payload)
    if not from_phone or not text:
        return jsonify({"status": "ok"}), 200  # ignore non-message events

    msg = text.strip()
    upper = msg.upper()

    # Always do lazy expiry check on every inbound message
    sub = mark_expired_if_needed(supabase, wa_phone=from_phone)

    # Commands
    if upper.startswith("UPGRADE"):
        # Expected: UPGRADE BASIC / UPGRADE STANDARD / UPGRADE PREMIUM
        parts = upper.split()
        if len(parts) < 2:
            send_whatsapp_text(from_phone, "Usage: UPGRADE BASIC | UPGRADE STANDARD | UPGRADE PREMIUM")
            return jsonify({"status": "ok"}), 200

        plan = parts[1].strip().upper()

        # Call our own Paystack initialize endpoint internally
        # (No need for callback page)
        init_res = requests.post(
            f"{os.getenv('APP_BASE_URL','').rstrip('/')}/paystack/initialize",
            json={"wa_phone": from_phone, "plan": plan},
            timeout=30,
        )

        if init_res.status_code != 200:
            try:
                err = init_res.json()
            except Exception:
                err = {"raw": init_res.text}
            send_whatsapp_text(from_phone, f"Payment init failed. Try again.\nDetails: {err.get('message','')}")
            return jsonify({"status": "ok"}), 200

        data = init_res.json()
        pay_url = data["authorization_url"]

        send_whatsapp_text(
            from_phone,
            f"✅ Upgrade to {plan}\n\nPay here:\n{pay_url}\n\nAfter payment, you will be activated automatically."
        )
        return jsonify({"status": "ok"}), 200

    if upper == "STATUS":
        if sub.is_active:
            exp = sub.expires_at.isoformat() if sub.expires_at else "N/A"
            send_whatsapp_text(from_phone, f"✅ Active plan: {sub.plan}\nExpires: {exp}")
        else:
            send_whatsapp_text(
                from_phone,
                "❌ No active subscription.\n\nUpgrade:\nUPGRADE BASIC\nUPGRADE STANDARD\nUPGRADE PREMIUM"
            )
        return jsonify({"status": "ok"}), 200

    # Example: Protect premium features
    # (Replace PREMIUM_FEATURE with your real command)
    if upper.startswith("PREMIUM_FEATURE"):
        if not sub.is_active:
            send_whatsapp_text(
                from_phone,
                "⚠️ This feature requires an active subscription.\n\nUpgrade:\nUPGRADE BASIC\nUPGRADE STANDARD\nUPGRADE PREMIUM"
            )
            return jsonify({"status": "ok"}), 200

        # If active: continue your premium feature logic here
        send_whatsapp_text(from_phone, "✅ Access granted. Running premium feature...")
        return jsonify({"status": "ok"}), 200

    # Default reply
    send_whatsapp_text(
        from_phone,
        "Hello. Commands:\nSTATUS\nUPGRADE BASIC\nUPGRADE STANDARD\nUPGRADE PREMIUM"
    )
    return jsonify({"status": "ok"}), 200
