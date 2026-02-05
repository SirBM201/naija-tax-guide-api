import os
import re
import requests
from flask import Blueprint, request, jsonify

bp = Blueprint("whatsapp", __name__)

WA_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
BASE_URL = os.getenv("PUBLIC_API_BASE_URL", "").strip()  # e.g. https://your-api.com

CODE_RE = re.compile(r"(?:^|\b)([A-Z0-9]{6,12})(?:\b|$)", re.I)

def wa_send_text(to_wa_id: str, text: str):
    url = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WA_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to_wa_id,
        "type": "text",
        "text": {"body": text}
    }
    requests.post(url, headers=headers, json=payload, timeout=15)

def extract_text_message(payload: dict):
    try:
        entry = payload["entry"][0]
        change = entry["changes"][0]
        value = change["value"]
        msg = value["messages"][0]
        wa_id = msg["from"]
        text = msg.get("text", {}).get("body", "") or ""
        return wa_id, text
    except Exception:
        return None, None

@bp.post("/whatsapp/webhook")
def whatsapp_webhook():
    data = request.get_json(silent=True) or {}
    wa_id, text = extract_text_message(data)

    # Always ACK quickly
    if not wa_id:
        return jsonify({"ok": True})

    t = (text or "").strip()
    upper = t.upper()

    # Accept "LINK XXXXXXXX" or just "XXXXXXXX"
    code = None
    if upper.startswith("LINK "):
        code = upper.replace("LINK", "", 1).strip()
    else:
        m = CODE_RE.search(upper)
        if m and len(upper.split()) <= 3:
            code = m.group(1)

    if not code:
        # Ignore normal chat OR optionally respond help
        return jsonify({"ok": True})

    # Call your own consume API (or call Supabase RPC directly)
    try:
        resp = requests.post(
            f"{BASE_URL}/api/link-tokens/consume",
            json={"provider": "wa", "code": code, "provider_user_id": wa_id},
            timeout=15,
        )
        j = resp.json()
    except Exception:
        wa_send_text(wa_id, "⚠️ Linking failed due to network error. Please try again.")
        return jsonify({"ok": True})

    if j.get("ok"):
        wa_send_text(wa_id, "✅ Linked successfully! Your WhatsApp is now connected to your account.")
    else:
        wa_send_text(wa_id, "❌ Invalid or expired code. Please request a new code from your dashboard/admin.")

    return jsonify({"ok": True})
