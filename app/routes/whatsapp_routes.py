import os
import logging
import requests
from flask import Blueprint, request, jsonify, current_app

bp = Blueprint("whatsapp", __name__)
log = logging.getLogger(__name__)

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_API_VERSION = os.getenv("WHATSAPP_API_VERSION", "v22.0")

GRAPH_BASE = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}"


def _send_wa_text(to_id: str, text: str):
    if not WHATSAPP_TOKEN:
        return

    url = f"{GRAPH_BASE}/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    body = {
        "messaging_product": "whatsapp",
        "to": to_id,
        "type": "text",
        "text": {"body": text[:3900]},
    }

    r = requests.post(url, headers=headers, json=body, timeout=20)
    if r.status_code >= 300:
        log.error("WhatsApp send failed: %s %s", r.status_code, r.text)


def _extract(payload):
    try:
        entry = payload["entry"][0]
        change = entry["changes"][0]
        value = change["value"]
        msg = value["messages"][0]
        return msg["from"], msg["text"]["body"]
    except Exception:
        return None, None


@bp.get("/whatsapp/webhook")
def verify():
    if (
        request.args.get("hub.mode") == "subscribe"
        and request.args.get("hub.verify_token") == WHATSAPP_VERIFY_TOKEN
    ):
        return request.args.get("hub.challenge"), 200
    return "forbidden", 403


@bp.post("/whatsapp/webhook")
def webhook():
    payload = request.get_json(silent=True) or {}
    wa_id, text = _extract(payload)

    if not wa_id or not text:
        return jsonify({"ok": True})

    log.info("WA inbound %s: %s", wa_id, text)

    client = current_app.test_client()
    r = client.post("/ask", json={
        "provider": "wa",
        "provider_user_id": wa_id,
        "question": text,
        "mode": "text",
        "lang": "en",
    })

    data = r.get_json(silent=True) or {}
    reply = data.get("answer") or "Sorry, I couldn’t process that."

    _send_wa_text(wa_id, reply)
    return jsonify({"ok": True})
