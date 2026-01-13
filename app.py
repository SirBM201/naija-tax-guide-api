# app.py
import os
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from supabase import create_client
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

APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

# CORS allowed origins: comma-separated
# Example:
# ALLOWED_ORIGINS=http://localhost:3000,https://thecre8hub.com,https://www.thecre8hub.com
ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://thecre8hub.com",
        "https://www.thecre8hub.com",
    ]

CORS(
    app,
    resources={r"/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "x-paystack-signature"],
)

# Supabase
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing.")
sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Paystack Config
# ------------------------------------------------------------
PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify/"
CURRENCY = "NGN"

# IMPORTANT: KOBO
PLAN_PRICES = {
    "monthly": 300000,    # ₦3,000
    "quarterly": 800000,  # ₦8,000
    "yearly": 3000000,    # ₦30,000
}

DEFAULT_PLAN_DURATION_DAYS = int(os.getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def safe_text(v: Any) -> str:
    return (v or "").strip()

def normalize_wa_phone(wa_phone: str) -> str:
    # keep digits only (frontend uses: 234xxxxxxxxxx, no plus)
    return re.sub(r"\D", "", (wa_phone or "").strip())

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack header: x-paystack-signature
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

def safe_email(email: str, wa_phone: str) -> str:
    """
    Paystack requires email. If user email missing/invalid, generate a placeholder.
    """
    email = (email or "").strip()
    if email and "@" in email:
        return email
    digits = re.sub(r"\D", "", wa_phone or "")
    if not digits:
        digits = uuid.uuid4().hex[:10]
    return f"user_{digits}@thecre8hub.local"

def days_for_plan(plan: str) -> int:
    return {"monthly": 30, "quarterly": 90, "yearly": 365}.get(plan, DEFAULT_PLAN_DURATION_DAYS)

# ------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------
def record_paystack_event(event_id: str, event_type: str, reference: Optional[str], payload: Dict[str, Any]) -> bool:
    """
    Returns True if inserted; False if duplicate.
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
        logging.warning("paystack_events insert failed/duplicate: %s", str(e))
        return False

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    """
    REQUIRED columns in user_subscriptions:
      wa_phone (unique), plan, status, expires_at, updated_at
    """
    plan = (plan or "").lower()
    wa_phone = normalize_wa_phone(wa_phone)

    expires_at = iso(now_utc() + timedelta(days=days_for_plan(plan)))
    sb.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

def get_subscription(wa_phone: str) -> Optional[Dict[str, Any]]:
    try:
        res = sb.table("user_subscriptions").select("*").eq("wa_phone", wa_phone).limit(1).execute()
        if res.data:
            return res.data[0]
    except Exception as e:
        logging.warning("get_subscription error: %s", str(e))
    return None

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    # Frontend route-check expects fetchable JSON
    return jsonify({"ok": True})

# ---------------------------
# Paystack Initialize
# ---------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Expects JSON:
      { "wa_phone": "234xxxxxxxxxx", "email": "user@email.com", "plan": "monthly|quarterly|yearly" }

    Returns:
      { "status":"ok", "authorization_url":"...", "reference":"..." }
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

    amount_kobo = int(PLAN_PRICES[plan])
    reference = f"ntg_{uuid.uuid4().hex}"

    payload = {
        "email": safe_email(email, wa_phone),
        "amount": amount_kobo,
        "currency": CURRENCY,
        "reference": reference,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
        }
    }

    # Optional: Paystack redirect back to your website
    if APP_BASE_URL:
        payload["callback_url"] = f"{APP_BASE_URL}/payment-success?reference={reference}"

    try:
        r = requests.post(PAYSTACK_INIT_URL, headers=paystack_headers(), json=payload, timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            logging.error("Paystack init failed: %s %s", r.status_code, resp)
            return jsonify({"status": "error", "error": "paystack_init_failed", "detail": resp}), 502

        auth_url = resp["data"]["authorization_url"]
        return jsonify({"status": "ok", "authorization_url": auth_url, "reference": reference}), 200

    except Exception as e:
        logging.exception("Initialize exception")
        return jsonify({"status": "error", "error": str(e)}), 500

# ---------------------------
# Paystack Verify (THIS FIXES YOUR FRONTEND)
# ---------------------------
@app.post("/paystack/verify")
def paystack_verify():
    """
    Expects: { "reference": "..." }

    Returns (frontend expects this shape):
      { ok: true, paid: true/false, reference, plan?, wa_phone?, message? }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}
    reference = safe_text(data.get("reference"))

    if not reference:
        return jsonify({"ok": False, "error": "reference required"}), 400

    try:
        r = requests.get(f"{PAYSTACK_VERIFY_URL}{reference}", headers=paystack_headers(), timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": resp}), 502

        d = resp.get("data", {}) or {}
        status = (d.get("status") or "").lower()   # "success", "failed", "abandoned"
        paid = status == "success"

        metadata = d.get("metadata", {}) or {}
        wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
        plan = str(metadata.get("plan") or "").lower()

        # If successful, activate subscription
        if paid and wa_phone and plan in PLAN_PRICES:
            activate_user_subscription(wa_phone, plan)

        return jsonify({
            "ok": True,
            "paid": bool(paid),
            "reference": reference,
            "status": status,
            "wa_phone": wa_phone or None,
            "plan": plan or None,
            "message": "Payment verified and subscription activated." if paid else "Payment not successful yet."
        }), 200

    except Exception as e:
        logging.exception("Verify exception")
        return jsonify({"ok": False, "error": str(e)}), 500

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

    # Idempotency: avoid double-processing
    record_paystack_event(event_id, event_type, reference, payload)

    if event_type == "charge.success":
        metadata = data.get("metadata", {}) or {}
        purpose = metadata.get("purpose")
        wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
        plan = str(metadata.get("plan") or "").lower()

        if purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
            activate_user_subscription(wa_phone, plan)

    return "OK", 200

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
