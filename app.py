import os
import re
import json
import hmac
import uuid
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App
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

# Your frontend origins (comma-separated)
# Example:
# FRONTEND_ORIGINS=http://localhost:3000,https://thecre8hub.com,https://www.thecre8hub.com
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "http://localhost:3000").strip()

# Where Paystack should redirect after payment (optional)
# Example:
# APP_BASE_URL=https://thecre8hub.com
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

DEFAULT_PLAN_DURATION_DAYS = int(os.getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))

sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

GRAPH_API_BASE = "https://graph.facebook.com/v20.0"
PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify/"
CURRENCY = "NGN"

# ------------------------------------------------------------
# CORS (Browser needs this; Postman doesn't)
# ------------------------------------------------------------
allowed_origins = [o.strip() for o in FRONTEND_ORIGINS.split(",") if o.strip()]
CORS(
    app,
    resources={r"/*": {"origins": allowed_origins}},
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# ------------------------------------------------------------
# Pricing (kobo)
# ------------------------------------------------------------
# 3000 NGN => 300000 kobo
PLAN_PRICES_KOBO = {
    "monthly": 3000 * 100,
    "quarterly": 8000 * 100,
    "yearly": 30000 * 100,
}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def safe_text(x: Any) -> str:
    return (x or "").strip()

def normalize_wa_phone(wa_phone: str) -> str:
    # keep digits only
    s = re.sub(r"\D", "", safe_text(wa_phone))
    return s

def new_reference(prefix: str = "ntg") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    if not signature or not PAYSTACK_SECRET_KEY:
        return False
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(computed, signature)

def wa_send_text(to_phone_digits: str, text: str) -> None:
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        logging.warning("WhatsApp env not set; skipping WA send.")
        return

    url = f"{GRAPH_API_BASE}/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone_digits,
        "type": "text",
        "text": {"body": text}
    }
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    if r.status_code >= 300:
        logging.error("WhatsApp send failed: %s %s", r.status_code, r.text)
    else:
        logging.info("WhatsApp message sent to %s", to_phone_digits)

def activate_subscription(wa_phone: str, plan: str) -> None:
    days = {"monthly": 30, "quarterly": 90, "yearly": 365}.get(plan, DEFAULT_PLAN_DURATION_DAYS)
    expires_at = iso(now_utc() + timedelta(days=days))

    sb.table("subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc()),
    }, on_conflict="wa_phone").execute()

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"status": "ok"})

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
# Paystack Initialize (Frontend calls this)
# ---------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Expected JSON body:
    {
      "wa_phone": "234xxxxxxxxxx",
      "email": "info@thecre8hub.com",
      "plan": "monthly|quarterly|yearly"
    }
    Returns:
    { "authorization_url": "...", "reference": "..." }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"status": "error", "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}
    wa_phone = normalize_wa_phone(data.get("wa_phone"))
    email = safe_text(data.get("email"))
    plan = safe_text(data.get("plan")).lower()

    if not wa_phone:
        return jsonify({"status": "error", "error": "wa_phone required"}), 400
    if not email or "@" not in email:
        return jsonify({"status": "error", "error": "valid email required"}), 400
    if plan not in PLAN_PRICES_KOBO:
        return jsonify({"status": "error", "error": f"invalid plan. allowed={list(PLAN_PRICES_KOBO.keys())}"}), 400

    amount_kobo = int(PLAN_PRICES_KOBO[plan])
    reference = new_reference("cre8hub")

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

    # Optional: callback (Paystack will redirect here after payment)
    if APP_BASE_URL:
        payload["callback_url"] = f"{APP_BASE_URL}/payment-success"

    try:
        r = requests.post(PAYSTACK_INIT_URL, headers=paystack_headers(), json=payload, timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            logging.error("Paystack init failed: %s %s", r.status_code, resp)
            return jsonify({"status": "error", "error": "paystack_init_failed", "detail": resp}), 502

        auth_url = resp["data"]["authorization_url"]
        return jsonify({"authorization_url": auth_url, "reference": reference}), 200

    except Exception as e:
        logging.exception("Initialize error")
        return jsonify({"status": "error", "error": str(e)}), 500

# ---------------------------
# Paystack Webhook (Paystack calls this)
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

    if event_type == "charge.success":
        metadata = data.get("metadata", {}) or {}
        wa_phone = normalize_wa_phone(metadata.get("wa_phone"))
        plan = safe_text(metadata.get("plan")).lower()

        if wa_phone and plan in PLAN_PRICES_KOBO:
            try:
                activate_subscription(wa_phone, plan)
                wa_send_text(
                    wa_phone,
                    f"Payment received successfully. Your {plan.upper()} plan is now ACTIVE. Reply MENU to continue."
                )
            except Exception as e:
                logging.exception("Subscription activation failed: %s", str(e))

    return "OK", 200

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
