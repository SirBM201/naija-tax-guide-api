import os
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)

# ------------------------------------------------------------
# CORS (REQUIRED for Website + Paystack)
# ------------------------------------------------------------
CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                "http://localhost:3000",
                "https://thecre8hub.com",
                "https://www.thecre8hub.com",
                "https://developed-lizabeth-bmsconcept-e65bfd1d.koyeb.app"
            ]
        }
    },
    supports_credentials=True,
)

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")

FRONTEND_BASE_URL = os.getenv(
    "FRONTEND_BASE_URL",
    "https://thecre8hub.com"
)

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Utils
# ------------------------------------------------------------
def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()

PLAN_DAYS = {
    "monthly": 30,
    "quarterly": 90,
    "yearly": 365,
}

PLAN_AMOUNTS_KOBO = {
    "monthly": 300000,
    "quarterly": 800000,
    "yearly": 3000000,
}

# ------------------------------------------------------------
# Paystack Initialize
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    data = request.get_json(force=True)

    email = data.get("email")
    plan = data.get("plan")

    if not email or plan not in PLAN_AMOUNTS_KOBO:
        return jsonify({"error": "Invalid request"}), 400

    payload = {
        "email": email,
        "amount": PLAN_AMOUNTS_KOBO[plan],
        "currency": "NGN",
        "callback_url": f"{FRONTEND_BASE_URL}/payment-success",
        "metadata": {
            "plan": plan
        }
    }

    res = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers={
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        },
        json=payload,
        timeout=30
    )

    return jsonify(res.json()), res.status_code

# ------------------------------------------------------------
# Paystack Webhook
# ------------------------------------------------------------
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data()
    signature = request.headers.get("x-paystack-signature", "")

    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode(),
        raw,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed, signature):
        return "Invalid signature", 401

    event = json.loads(raw)

    if event.get("event") == "charge.success":
        data = event["data"]
        email = data["customer"]["email"]
        plan = data["metadata"]["plan"]
        reference = data["reference"]

        start = now_utc()
        end = start + timedelta(days=PLAN_DAYS[plan])

        supabase.table("subscriptions").upsert({
            "user_id": None,  # resolved later via auth
            "plan": plan,
            "status": "active",
            "start_at": iso(start),
            "end_at": iso(end),
            "paystack_ref": reference,
            "amount_kobo": data["amount"],
            "currency": "NGN",
            "updated_at": iso(now_utc())
        }, on_conflict="paystack_ref").execute()

    return "ok", 200

# ------------------------------------------------------------
# Health Check (Koyeb / Paystack / Meta)
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200
