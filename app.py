import os
import json
import hmac
import hashlib
import logging
from typing import Any, Dict, Optional

import requests
from flask import Flask, request, jsonify
from supabase import create_client
from flask_cors import CORS

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")

sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

GRAPH_API_BASE = "https://graph.facebook.com/v20.0"


def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack signature header: x-paystack-signature
    signature = HMAC_SHA512(body, PAYSTACK_SECRET_KEY).hexdigest()
    """
    if not signature or not PAYSTACK_SECRET_KEY:
        return False
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


def wa_send_text(to_phone_e164: str, text: str) -> None:
    url = f"{GRAPH_API_BASE}/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone_e164,
        "type": "text",
        "text": {"body": text}
    }
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    if r.status_code >= 300:
        logging.error("WhatsApp send failed: %s %s", r.status_code, r.text)
    else:
        logging.info("WhatsApp message sent to %s", to_phone_e164)


def record_paystack_event(event_id: str, event_type: str, reference: Optional[str], payload: Dict[str, Any]) -> bool:
    """
    Returns True if inserted; False if duplicate (already processed).
    """
    try:
        sb.table("paystack_events").insert({
            "event_id": event_id,
            "event_type": event_type,
            "reference": reference,
            "payload": payload
        }).execute()
        return True
    except Exception as e:
        # Duplicate unique event_id => already processed
        logging.warning("Event insert failed/duplicate: %s", str(e))
        return False


def credit_topup(user_id: str, credits: int) -> None:
    # call SQL function: add_ai_credits(user_id, credits)
    sb.rpc("add_ai_credits", {"p_user_id": user_id, "p_credits_added": credits}).execute()


@app.get("/health")
def health():
    return jsonify({"ok": True})


# ---------------------------
# WhatsApp Webhook (Meta)
# ---------------------------
@app.get("/webhooks/whatsapp")
def whatsapp_verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200
    return "Verification failed", 403


@app.post("/webhooks/whatsapp")
def whatsapp_inbound():
    data = request.get_json(force=True, silent=True) or {}
    logging.info("WhatsApp inbound: %s", json.dumps(data)[:2000])

    # TODO: parse incoming message + route to your UX/menu logic
    # For now: ACK fast
    return "OK", 200


# ---------------------------
# Paystack Webhook
# ---------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    raw_body = request.get_data()
    signature = request.headers.get("x-paystack-signature", "")

    if not verify_paystack_signature(raw_body, signature):
        return "Invalid signature", 401

    payload = request.get_json(force=True, silent=True) or {}
    event_type = payload.get("event", "")
    data = payload.get("data", {}) or {}

    # Use a stable idempotency key
    # Paystack data can have: id, reference
    event_id = str(data.get("id") or data.get("reference") or "")
    reference = str(data.get("reference") or "")

    if not event_id:
        return "Missing event id", 400

    if not record_paystack_event(event_id, event_type, reference, payload):
        return "Duplicate ignored", 200

    # Handle successful charges
    if event_type == "charge.success":
        # You MUST pass metadata when initializing Paystack transaction
        # Example metadata:
        #  { "user_id": "<uuid>", "purpose": "subscription"|"topup", "topup_credits": 300, "wa_phone": "+234..." }
        metadata = data.get("metadata", {}) or {}
        user_id = metadata.get("user_id")
        purpose = metadata.get("purpose")
        wa_phone = metadata.get("wa_phone")

        if purpose == "topup":
            topup_credits = int(metadata.get("topup_credits") or 0)
            if user_id and topup_credits > 0:
                credit_topup(user_id, topup_credits)
                if wa_phone:
                    wa_send_text(
                        wa_phone,
                        f"Top-up successful. {topup_credits} AI credits added to your account. Thank you."
                    )

        elif purpose == "subscription":
            # Here you update subscriptions table (paid status, plan, expires_at etc.)
            # Keep it simple for now: notify user
            if wa_phone:
                wa_send_text(
                    wa_phone,
                    "Subscription payment received successfully. Your plan is now active. Reply MENU to continue."
                )

    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
