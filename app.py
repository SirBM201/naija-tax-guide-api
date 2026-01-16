# app.py
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

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ------------------------------------------------------------
# App + Logging
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()

APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/").strip()

# Admin key for protected admin/cron endpoints
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

# SMTP (optional)
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER).strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Naija Tax Guide").strip()

# Optional: allow manual webhook test without paystack signature
# Set this in Koyeb if you want.
WEBHOOK_TEST_SECRET = os.getenv("WEBHOOK_TEST_SECRET", "").strip()

# CORS allowed origins
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
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "x-paystack-signature",
        "x-admin-key",
        "x-webhook-test",  # for manual testing
    ],
)

# Supabase client
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing.")
sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Paystack Config
# ------------------------------------------------------------
PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify/"
CURRENCY = "NGN"

# KOBO
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
    return re.sub(r"\D", "", (wa_phone or "").strip())

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack webhook signature is HMAC SHA512 using YOUR SECRET KEY.
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
# Admin Security Helpers
# ------------------------------------------------------------
def require_admin(req) -> bool:
    if not ADMIN_API_KEY:
        return False
    key = (req.headers.get("x-admin-key") or "").strip()
    return key == ADMIN_API_KEY

# ------------------------------------------------------------
# Email helper
# ------------------------------------------------------------
def send_email(to_email: str, subject: str, html_body: str) -> None:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        raise Exception("SMTP not configured (SMTP_HOST/SMTP_USER/SMTP_PASS missing).")

    msg = MIMEMultipart("alternative")
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM}>"
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, [to_email], msg.as_string())

# ------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------
def record_paystack_event(event_id: str, event_type: str, reference: Optional[str], payload: Dict[str, Any]) -> bool:
    """
    Returns True if inserted; False if duplicate.
    Requires paystack_events.event_id UNIQUE (you already created it).
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

def upsert_payment_row(
    reference: str,
    wa_phone: Optional[str],
    plan: Optional[str],
    amount_kobo: Optional[int],
    currency: str,
    status: str,
    provider: str = "paystack",
    paid_at: Optional[str] = None,
    raw_event: Optional[Dict[str, Any]] = None,
    email: Optional[str] = None,
) -> None:
    row = {
        "reference": reference,
        "wa_phone": wa_phone,
        "provider": provider,
        "plan": plan,
        "amount_kobo": amount_kobo,
        "currency": currency,
        "status": status,
        "raw_event": raw_event or {},
    }
    if paid_at:
        row["paid_at"] = paid_at
    if email:
        row["email"] = email

    sb.table("payments").upsert(row, on_conflict="reference").execute()

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

# ---------------------------
# Paystack Webhook
# ---------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    """
    Paystack hits this endpoint with:
      - POST JSON body
      - header: x-paystack-signature

    We also allow a manual test mode:
      - If WEBHOOK_TEST_SECRET is set, you can send:
          header x-webhook-test: <WEBHOOK_TEST_SECRET>
        and we'll accept without signature.
    """
    raw_body = request.get_data() or b""
    signature = request.headers.get("x-paystack-signature", "")

    # Manual test mode (optional)
    test_header = (request.headers.get("x-webhook-test") or "").strip()
    if WEBHOOK_TEST_SECRET and test_header == WEBHOOK_TEST_SECRET:
        logging.info("Webhook accepted via x-webhook-test header (manual test).")
    else:
        if not verify_paystack_signature(raw_body, signature):
            logging.warning("Invalid Paystack signature.")
            return "Invalid signature", 401

    payload = request.get_json(force=True, silent=True) or {}
    event_type = str(payload.get("event") or "")
    data = payload.get("data", {}) or {}

    # Paystack commonly provides:
    #   data.id (numeric), data.reference (string)
    reference = str(data.get("reference") or "")
    event_id = str(data.get("id") or reference or "")

    if not event_id:
        return "Missing event id", 400

    # Idempotency: stop if we've seen this event_id already
    inserted = record_paystack_event(event_id, event_type, reference, payload)
    if not inserted:
        return "OK", 200

    status = (data.get("status") or "").lower()
    amount_kobo = data.get("amount")
    currency = data.get("currency") or CURRENCY

    customer = data.get("customer", {}) or {}
    email = (customer.get("email") or "").strip()

    metadata = data.get("metadata", {}) or {}
    wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
    plan = str(metadata.get("plan") or "").lower()
    purpose = str(metadata.get("purpose") or "")

    # Always upsert into payments
    try:
        paid_at = iso(now_utc()) if event_type == "charge.success" else None
        upsert_payment_row(
            reference=reference or event_id,
            wa_phone=wa_phone or None,
            plan=plan or None,
            amount_kobo=int(amount_kobo) if amount_kobo is not None else None,
            currency=currency,
            status="success" if event_type == "charge.success" else (status or event_type),
            provider="paystack",
            paid_at=paid_at,
            raw_event=payload,
            email=email or None,
        )
    except Exception:
        logging.exception("Failed to upsert payments row (webhook)")

    # Activate only on success
    if event_type == "charge.success":
        if purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
            try:
                activate_user_subscription(wa_phone, plan)
            except Exception:
                logging.exception("activate_user_subscription failed")

    return "OK", 200

# ------------------------------------------------------------
# Main (local)
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
