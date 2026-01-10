import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, request, jsonify

from supabase import create_client

# ✅ NEW: CORS
from flask_cors import CORS

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
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

# Frontend origins allowed (comma-separated)
FRONTEND_ORIGINS = os.getenv(
    "FRONTEND_ORIGINS",
    "http://localhost:3000"
)

# Where user returns after Paystack
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000")

# ------------------------------------------------------------
# Supabase client
# ------------------------------------------------------------
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("Supabase env vars not set (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY else None


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


# ------------------------------------------------------------
# ✅ CORS SETUP (FINAL)
# ------------------------------------------------------------
def _parse_origins(csv: str) -> list[str]:
    items = [x.strip() for x in (csv or "").split(",")]
    return [x for x in items if x]

ALLOWED_ORIGINS = _parse_origins(FRONTEND_ORIGINS)

CORS(
    app,
    resources={
        r"/paystack/*": {"origins": ALLOWED_ORIGINS},
        r"/health": {"origins": "*"},
    },
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# ------------------------------------------------------------
# Health
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# ------------------------------------------------------------
# Plans mapping helper (professional standard)
# ------------------------------------------------------------
VALID_PLANS = {"monthly", "quarterly", "yearly"}


def get_plan_from_db(plan_code: str) -> Tuple[int, int, str]:
    """
    Returns: (amount_kobo, duration_days, currency)
    Reads from public.plans where plan == plan_code
    """
    if not supabase:
        raise RuntimeError("Supabase client not configured")

    row = (
        supabase.table("plans")
        .select("amount_kobo,duration_days,currency")
        .eq("plan", plan_code)
        .single()
        .execute()
    )

    data = row.data or {}
    amount_kobo = int(data.get("amount_kobo", 0))
    duration_days = int(data.get("duration_days", 0))
    currency = (data.get("currency") or "NGN").upper()

    if amount_kobo <= 0 or duration_days <= 0:
        raise ValueError(f"Plan not configured correctly in DB: {plan_code}")

    return amount_kobo, duration_days, currency


def activate_user_subscription(wa_phone: str, plan: str, paystack_reference: Optional[str] = None) -> None:
    """
    Canonical: write to public.user_subscriptions (WhatsApp-first).
    This matches your WhatsApp app model and is safest for now.
    """
    if not supabase:
        raise RuntimeError("Supabase client not configured")

    amount_kobo, duration_days, currency = get_plan_from_db(plan)

    expires_at = now_utc() + timedelta(days=duration_days)

    payload: Dict[str, Any] = {
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": iso(expires_at),
        "updated_at": iso(now_utc()),
        "amount_kobo": amount_kobo,
        "currency": currency,
        "last_event": "subscription.activated",
    }
    if paystack_reference:
        payload["paystack_reference"] = paystack_reference

    supabase.table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()


# ------------------------------------------------------------
# ✅ Paystack: Initialize (FINAL)
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Body: { wa_phone: "234xxxxxxxxxx", email: "x@y.com", plan: "monthly|quarterly|yearly" }
    Returns: { authorization_url, reference }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"error": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}

    wa_phone = (body.get("wa_phone") or "").strip()
    email = (body.get("email") or "").strip()
    plan = (body.get("plan") or "").strip().lower()

    if not wa_phone or not email or plan not in VALID_PLANS:
        return jsonify({"error": "Invalid request. Expected wa_phone, email, plan (monthly|quarterly|yearly)."}), 400

    try:
        amount_kobo, duration_days, currency = get_plan_from_db(plan)
    except Exception as e:
        logging.exception("Plan lookup failed")
        return jsonify({"error": f"Plan lookup failed: {str(e)}"}), 400

    callback_url = f"{FRONTEND_BASE_URL.rstrip('/')}/payment-success"

    paystack_payload = {
        "email": email,
        "amount": amount_kobo,
        "currency": currency,
        "callback_url": callback_url,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "duration_days": duration_days,
        },
    }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    try:
        r = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=headers,
            data=json.dumps(paystack_payload),
            timeout=30,
        )
        data = r.json()
    except Exception as e:
        logging.exception("Paystack initialize request failed")
        return jsonify({"error": f"Paystack initialize request failed: {str(e)}"}), 502

    if not data.get("status"):
        # Paystack returned an error
        message = data.get("message") or "Paystack initialize failed"
        return jsonify({"error": message, "raw": data}), 400

    auth_url = data["data"]["authorization_url"]
    reference = data["data"]["reference"]

    # Optional: record "pending" state now (good practice)
    if supabase:
        try:
            supabase.table("user_subscriptions").upsert(
                {
                    "wa_phone": wa_phone,
                    "plan": plan,
                    "status": "pending",
                    "paystack_reference": reference,
                    "updated_at": iso(now_utc()),
                    "amount_kobo": amount_kobo,
                    "currency": currency,
                    "last_event": "charge.initialize",
                },
                on_conflict="wa_phone",
            ).execute()
        except Exception:
            logging.exception("Failed to upsert pending subscription")

    return jsonify({"authorization_url": auth_url, "reference": reference})


# ------------------------------------------------------------
# ✅ Paystack: Webhook (FINAL, signature verified)
# ------------------------------------------------------------
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_WEBHOOK_SECRET not set", 500

    expected = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_name = event.get("event", "")
    data = event.get("data") or {}
    reference = data.get("reference")

    metadata = data.get("metadata") or {}
    wa_phone = (metadata.get("wa_phone") or "").strip()
    plan = (metadata.get("plan") or "").strip().lower()

    # Always log (helps debug)
    logging.info(f"Paystack webhook event={event_name} reference={reference} wa_phone={wa_phone} plan={plan}")

    if not wa_phone:
        return "ok", 200

    # Update last_event for tracking
    if supabase:
        try:
            supabase.table("user_subscriptions").upsert(
                {
                    "wa_phone": wa_phone,
                    "paystack_reference": reference,
                    "last_event": event_name,
                    "updated_at": iso(now_utc()),
                },
                on_conflict="wa_phone",
            ).execute()
        except Exception:
            logging.exception("Failed to update last_event")

    if event_name == "charge.success":
        try:
            if plan not in VALID_PLANS:
                # fallback if metadata missing
                plan = "monthly"
            activate_user_subscription(wa_phone=wa_phone, plan=plan, paystack_reference=reference)
        except Exception:
            logging.exception("Failed to activate subscription")

    return "ok", 200
