# app/routes/whatsapp_routes.py
import os
import logging
import requests
from flask import Blueprint, request, jsonify, current_app

bp = Blueprint("whatsapp", __name__)
log = logging.getLogger(__name__)

# Meta WhatsApp Cloud API
VERIFY_TOKEN = (os.getenv("WHATSAPP_VERIFY_TOKEN") or "").strip()
ACCESS_TOKEN = (os.getenv("WHATSAPP_ACCESS_TOKEN") or "").strip()
PHONE_NUMBER_ID = (os.getenv("WHATSAPP_PHONE_NUMBER_ID") or "").strip()

GRAPH_API = "https://graph.facebook.com/v19.0"


def _send_whatsapp_text(to_phone: str, text: str) -> None:
    if not (ACCESS_TOKEN and PHONE_NUMBER_ID):
        log.warning("WhatsApp send skipped: missing ACCESS_TOKEN or PHONE_NUMBER_ID")
        return

    url = f"{GRAPH_API}/{PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {ACCESS_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code not in (200, 201):
            log.error("WhatsApp send failed: %s %s", r.status_code, r.text[:400])
    except Exception:
        log.exception("WhatsApp send exception")


def _call_ask(provider_user_id: str, question: str) -> str:
    """
    Calls internal /ask using NEW format.
    provider_user_id = WhatsApp wa_id ("from")
    """
    try:
        client = current_app.test_client()
        resp = client.post(
            "/ask",
            json={
                "provider": "wa",
                "provider_user_id": provider_user_id,
                "question": question,
                "mode": "text",
                "lang": "en",
            },
        )
        data = resp.get_json(silent=True) or {}
        if isinstance(data, dict) and data.get("ok") is True and data.get("answer"):
            return str(data["answer"])
        return str(data.get("message") or "Sorry, I couldn't process that right now.")
    except Exception:
        log.exception("Internal /ask call failed")
        return "Sorry — something went wrong. Please try again."

@bp.get("/whatsapp/ping")
def whatsapp_ping():
    return jsonify(ok=True, service="whatsapp"), 200


@bp.get("/whatsapp/webhook")
def whatsapp_verify():
    """
    Meta verification callback
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token and VERIFY_TOKEN and token == VERIFY_TOKEN:
        return challenge, 200

    return "forbidden", 403


@bp.post("/whatsapp/webhook")
def whatsapp_webhook():
    """
    Incoming messages
    """
    data = request.get_json(silent=True) or {}
    log.info("WA webhook received")

    try:
        entry = (data.get("entry") or [{}])[0]
        changes = (entry.get("changes") or [{}])[0]
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            return jsonify(ok=True), 200

        msg = messages[0]
        wa_from = str(msg.get("from") or "").strip()          # user's WhatsApp number in string form
        msg_type = (msg.get("type") or "").strip()

        # text message
        text = ""
        if msg_type == "text":
            text = ((msg.get("text") or {}).get("body") or "").strip()

        if not wa_from or not text:
            return jsonify(ok=True), 200

        answer = _call_ask(provider_user_id=wa_from, question=text)
        _send_whatsapp_text(wa_from, answer)

        return jsonify(ok=True), 200

    except Exception:
        log.exception("WhatsApp webhook handler failed")
        return jsonify(ok=True), 200
