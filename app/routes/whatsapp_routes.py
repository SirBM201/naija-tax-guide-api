from flask import Blueprint, request, jsonify, current_app
import logging
import os
import requests

bp = Blueprint("whatsapp", __name__)
log = logging.getLogger(__name__)

TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN")
GRAPH = "https://graph.facebook.com/v22.0"


@bp.get("/whatsapp/webhook")
def verify():
    if request.args.get("hub.verify_token") == VERIFY_TOKEN:
        return request.args.get("hub.challenge"), 200
    return "forbidden", 403


@bp.post("/whatsapp/webhook")
def webhook():
    data = request.get_json(silent=True) or {}
    try:
        msg = data["entry"][0]["changes"][0]["value"]["messages"][0]
    except Exception:
        return jsonify(ok=True)

    wa_id = msg["from"]
    text = msg.get("text", {}).get("body", "").strip()
    if not text:
        return jsonify(ok=True)

    client = current_app.test_client()
    r = client.post("/ask", json={
        "provider": "wa",
        "provider_user_id": wa_id,
        "question": text,
    })
    answer = (r.get_json() or {}).get("answer") or "Sorry, try again."

    requests.post(
        f"{GRAPH}/{PHONE_ID}/messages",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={
            "messaging_product": "whatsapp",
            "to": wa_id,
            "type": "text",
            "text": {"body": answer},
        }
    )

    return jsonify(ok=True)

