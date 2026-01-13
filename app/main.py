# app/main.py
import os
import json
import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)

# 🔥 CORS (THIS FIXES YOUR ERROR)
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    allow_headers=["Content-Type", "Authorization", "x-admin-key"],
    methods=["GET", "POST", "OPTIONS"],
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("Supabase env missing")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Plans
# ------------------------------------------------------------
PLAN_RULES = {
    "monthly":   {"amount_kobo": 3000 * 100, "days": 30,  "currency": "NGN"},
    "quarterly": {"amount_kobo": 8000 * 100, "days": 90,  "currency": "NGN"},
    "yearly":    {"amount_kobo": 30000 * 100, "days": 365, "currency": "NGN"},
}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def require_admin(req) -> Optional[Any]:
    key = req.headers.get("x-admin-key", "")
    if not ADMIN_API_KEY or key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    days = PLAN_RULES[plan]["days"]
    expires_at = iso(now_utc() + timedelta(days=days))

    supabase.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc()),
    }, on_conflict="wa_phone").execute()

def upsert_pending_subscription(wa_phone: str, plan: str) -> None:
    supabase.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "pending",
        "expires_at": None,
        "updated_at": iso(now_utc()),
    }, on_conflict="wa_phone").execute()

# ------------------------------------------------------------
# Health
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

# ------------------------------------------------------------
# Paystack Initialize
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    body = request.get_json(silent=True) or {}

    email = body.get("email", "").strip().lower()
    wa_phone = body.get("wa_phone", "").strip()
    plan = body.get("plan", "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Invalid email"}), 400
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone required"}), 400
    if plan not in PLAN_RULES:
        return jsonify({"ok": False, "error": "Invalid plan"}), 400

    rule = PLAN_RULES[plan]
    reference = uuid.uuid4().hex[:10]

    supabase.table("payments").insert({
        "reference": reference,
        "wa_phone": wa_phone,
        "provider": "paystack",
        "plan": plan,
        "amount_kobo": rule["amount_kobo"],
        "currency": rule["currency"],
        "status": "pending",
        "created_at": iso(now_utc()),
        "paid_at": None,
        "email": email,
    }).execute()

    upsert_pending_subscription(wa_phone, plan)

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "email": email,
        "amount": rule["amount_kobo"],
        "reference": reference,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
        },
    }

    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    r = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers=headers,
        json=payload,
        timeout=25,
    )

    data = r.json()
    if not data.get("status"):
        return jsonify({"ok": False, "error": data.get("message")}), 400

    return jsonify({
        "ok": True,
        "authorization_url": data["data"]["authorization_url"],
        "reference": reference,
    })

# ------------------------------------------------------------
# Paystack Webhook
# ------------------------------------------------------------
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data()
    sig = request.headers.get("x-paystack-signature", "")

    expected = hmac.new(
        PAYSTACK_WEBHOOK_SECRET.encode(),
        raw,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    event = json.loads(raw.decode())
    data = event.get("data", {})
    reference = data.get("reference")

    if event.get("event") not in ("charge.success", "transaction.success"):
        return "ok", 200

    pay = supabase.table("payments").select("*").eq("reference", reference).single().execute().data

    supabase.table("payments").update({
        "status": "success",
        "paid_at": iso(now_utc()),
    }).eq("reference", reference).execute()

    activate_user_subscription(pay["wa_phone"], pay["plan"])
    return "ok", 200

# ------------------------------------------------------------
# Admin APIs
# ------------------------------------------------------------
@app.get("/admin/subscriptions")
def admin_subscriptions():
    auth = require_admin(request)
    if auth:
        return auth

    res = supabase.table("user_subscriptions") \
        .select("wa_phone,plan,status,expires_at,updated_at") \
        .order("updated_at", desc=True) \
        .execute()

    return jsonify(res.data or [])

@app.get("/admin/payments")
def admin_payments():
    auth = require_admin(request)
    if auth:
        return auth

    res = supabase.table("payments") \
        .select("reference,wa_phone,provider,plan,amount_kobo,currency,status,created_at,paid_at") \
        .order("created_at", desc=True) \
        .execute()

    return jsonify(res.data or [])
