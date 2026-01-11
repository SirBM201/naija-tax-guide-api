import os
import re
import uuid
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App + Logging
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")

# Your website base URL (for Paystack callback_url if you want it)
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

# CORS allowed origins: comma-separated
# Example:
# ALLOWED_ORIGINS=http://localhost:3000,https://thecre8hub.com,https://www.thecre8hub.com
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]

# Safe defaults if env not set
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://thecre8hub.com",
        "https://www.thecre8hub.com",
    ]

# Enable CORS (supports preflight OPTIONS automatically)
CORS(
    app,
    resources={r"/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "x-paystack-signature"],
)

sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

GRAPH_API_BASE = "https://graph.facebook.com/v20.0"

# ------------------------------------------------------------
# Paystack Config
# ------------------------------------------------------------
PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"
CURRENCY = "NGN"

# IMPORTANT: kobo amounts
# Monthly = 3000 NGN => 300000 kobo
# Quarterly = 8000 NGN => 800000 kobo
# Yearly = 30000 NGN => 3000000 kobo
PLAN_PRICES = {
    "monthly": 300000,
    "quarterly": 800000,
    "yearly": 3000000,
}

DEFAULT_PLAN_DURATION_DAYS = int(os.getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def safe_text(v: Any) -> str:
    return (v or "").strip()

def normalize_wa_phone(wa_phone: str) -> str:
    # Keep digits only (your UI uses "no plus sign", e.g. 234xxxxxxxxxx)
    return re.sub(r"\D", "", (wa_phone or "").strip())

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

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

# ------------------------------------------------------------
# WhatsApp
# ------------------------------------------------------------
def wa_send_text(to_phone_e164: str, text: str) -> None:
    if not (WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID):
        logging.warning("WhatsApp creds not set; skipping message send.")
        return

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

# ------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------
def record_paystack_event(event_id: str, event_type: str, reference: Optional[str], payload: Dict[str, Any]) -> bool:
    """
    Returns True if inserted; False if duplicate (already processed).
    Assumes paystack_events.event_id is UNIQUE in Supabase.
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
        logging.warning("Event insert failed/duplicate: %s", str(e))
        return False

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    """
    IMPORTANT: This is the exact pattern you told me to keep using.
    Ensure user_subscriptions has columns: wa_phone (unique), plan, status, expires_at, updated_at
    """
    # duration map (optional). If you want exact durations:
    days_map = {"monthly": 30, "quarterly": 90, "yearly": 365}
    days = days_map.get(plan, DEFAULT_PLAN_DURATION_DAYS)

    expires_at = iso(now_utc() + timedelta(days=days))
    sb.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"status": "ok"})

# ---------------------------
# Paystack Initialize (for website)
# ---------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Website -> Backend initialize.
    Expects JSON:
      { "wa_phone": "234xxxxxxxxxx", "email": "user@email.com", "plan": "monthly|quarterly|yearly" }

    Returns (IMPORTANT response shape):
      { "status": "ok", "authorization_url": "...", "reference": "..." }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"status": "error", "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}
    wa_phone = normalize_wa_phone(safe_text(data.get("wa_phone")))
    email = safe_text(data.get("email"))
    plan = safe_text(data.get("plan")).lower()

    if not wa_phone:
        return jsonify({"status": "error", "error": "wa_phone required"}), 400
    if plan not in PLAN_PRICES:
        return jsonify({"status": "error", "error": f"invalid plan. allowed={list(PLAN_PRICES.keys())}"}), 400
    if not email or "@" not in email:
        return jsonify({"status": "error", "error": "valid email required"}), 400

    amount_kobo = int(PLAN_PRICES[plan])
    reference = f"ntg_{uuid.uuid4().hex}"

    payload = {
        "email": email,
        "amount": amount_kobo,
        "currency": CURRENCY,
        "reference": reference,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
        }
    }

    # Optional callback URL (only if you have a page to land on)
    # You can set APP_BASE_URL=https://thecre8hub.com in Koyeb env
    if APP_BASE_URL:
        payload["callback_url"] = f"{APP_BASE_URL}/payment-success?reference={reference}"

    try:
        r = requests.post(PAYSTACK_INIT_URL, headers=paystack_headers(), json=payload, timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            logging.error("Paystack init failed: %s %s", r.status_code, resp)
            return jsonify({
                "status": "error",
                "error": "paystack_init_failed",
                "detail": resp
            }), 502

        auth_url = resp["data"]["authorization_url"]

        return jsonify({
            "status": "ok",
            "authorization_url": auth_url,
            "reference": reference
        }), 200

    except Exception as e:
        logging.exception("Initialize exception")
        return jsonify({"status": "error", "error": str(e)}), 500

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
    return "OK", 200

# ---------------------------
# Paystack Webhook
# ---------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    raw_body = request.get_data() or b""
    signature = request.headers.get("x-paystack-signature", "")

    if not verify_paystack_signature(raw_body, signature):
        return "Invalid signature", 401

    payload = request.get_json(force=True, silent=True) or {}
    event_type = payload.get("event", "")
    data = payload.get("data", {}) or {}

    event_id = str(data.get("id") or data.get("reference") or "")
    reference = str(data.get("reference") or "")

    if not event_id:
        return "Missing event id", 400

    if not record_paystack_event(event_id, event_type, reference, payload):
        return "Duplicate ignored", 200

    if event_type == "charge.success":
        metadata = data.get("metadata", {}) or {}
        purpose = metadata.get("purpose")
        wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
        plan = str(metadata.get("plan") or "").lower()

        if purpose == "subscription" and wa_phone and plan:
            # Activate subscription in DB
            activate_user_subscription(wa_phone, plan)

            # Notify user on WhatsApp (only works if you pass valid wa_phone e164 and have WA creds)
            # Your wa_phone from UI is digits only; if you want +, add it here:
            wa_send_text(wa_phone, "Subscription payment received successfully. Your plan is now active. Reply MENU to continue.")

    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
