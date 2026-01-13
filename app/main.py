import os
import json
import hmac
import hashlib
import logging
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# -----------------------------
# ENV
# -----------------------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip()  # e.g. https://xxxx.koyeb.app
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").strip()

SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587").strip() or "587")
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", "").strip()

DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://thecre8hub.com",
    "https://www.thecre8hub.com",
]

PLAN_AMOUNT_NGN = {
    "monthly": 3000,
    "quarterly": 8000,
    "yearly": 30000,
}

PLAN_DURATION_DAYS = {
    "monthly": 30,
    "quarterly": 90,
    "yearly": 365,
}

# -----------------------------
# Helpers
# -----------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def parse_origins(value: str):
    if not value:
        return DEFAULT_ORIGINS
    parts = [x.strip() for x in value.split(",")]
    return [x for x in parts if x]

def get_supabase():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Supabase env not set")
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def admin_required():
    if not ADMIN_API_KEY:
        return False
    key = request.headers.get("x-admin-key", "").strip()
    return key == ADMIN_API_KEY

def send_email_receipt(to_email: str, subject: str, body: str) -> None:
    # Optional: if SMTP not configured, silently skip
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and SMTP_FROM and to_email):
        return

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

def upsert_payment(reference: str, payload: Dict[str, Any]) -> None:
    sb = get_supabase()
    payload["updated_at"] = iso(now_utc())
    sb.table("paystack_payments").upsert(payload, on_conflict="reference").execute()

def activate_subscription(wa_phone: str, plan: str) -> str:
    sb = get_supabase()
    days = PLAN_DURATION_DAYS.get(plan, 30)
    expires_at = now_utc() + timedelta(days=days)

    sb.table("user_subscriptions").upsert(
        {
            "wa_phone": wa_phone,
            "plan": plan,
            "status": "active",
            "expires_at": iso(expires_at),
            "updated_at": iso(now_utc()),
        },
        on_conflict="wa_phone",
    ).execute()

    return iso(expires_at)

# -----------------------------
# App
# -----------------------------
app = Flask(__name__)

CORS(
    app,
    resources={r"/*": {"origins": parse_origins(CORS_ORIGINS)}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "x-admin-key"],
    max_age=86400,
)

@app.get("/health")
def health():
    return jsonify({"ok": True})

# ------------------------------------------------------------
# PAYSTACK: INITIALIZE
# Body: { email, wa_phone, plan, callback_url? }
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return jsonify({"ok": False, "error": "Supabase env not set"}), 500

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip()
    wa_phone = str(data.get("wa_phone", "")).strip()
    plan = str(data.get("plan", "")).strip().lower()
    callback_url = str(data.get("callback_url", "")).strip()

    if not email:
        return jsonify({"ok": False, "error": "email required"}), 400
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone required"}), 400
    if plan not in PLAN_AMOUNT_NGN:
        return jsonify({"ok": False, "error": "invalid plan"}), 400

    amount_ngn = PLAN_AMOUNT_NGN[plan]
    amount_kobo = int(amount_ngn * 100)

    # Paystack will redirect to callback_url with ?reference=xxx
    # If callback_url not provided, fall back to frontend /payment-success on same origin if known
    if not callback_url:
        callback_url = "http://localhost:3000/payment-success"

    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    # Metadata is IMPORTANT for webhook processing
    payload = {
        "email": email,
        "amount": amount_kobo,
        "callback_url": callback_url,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "product": "naija-tax-guide",
        },
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        res = r.json() if r.content else {}
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    if r.status_code >= 400 or res.get("status") is not True:
        return jsonify({"ok": False, "error": "paystack_init_failed", "detail": res}), 502

    d = res.get("data") or {}
    reference = d.get("reference")
    authorization_url = d.get("authorization_url")
    access_code = d.get("access_code")

    # Store initialized payment (audit + idempotency)
    upsert_payment(
        reference=reference,
        payload={
            "reference": reference,
            "wa_phone": wa_phone,
            "email": email,
            "plan": plan,
            "amount_kobo": amount_kobo,
            "currency": "NGN",
            "status": "initialized",
            "gateway_response": None,
            "raw": d,
        },
    )

    return jsonify({
        "ok": True,
        "plan": plan,
        "wa_phone": wa_phone,
        "amount": amount_ngn,
        "reference": reference,
        "authorization_url": authorization_url,
        "access_code": access_code,
    }), 200

# ------------------------------------------------------------
# PAYSTACK: VERIFY (used by /payment-success page)
# Body: { reference }
# ------------------------------------------------------------
@app.post("/paystack/verify")
def paystack_verify():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return jsonify({"ok": False, "error": "Supabase env not set"}), 500

    data = request.get_json(silent=True) or {}
    reference = str(data.get("reference", "")).strip()
    if not reference:
        return jsonify({"ok": False, "error": "reference required"}), 400

    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    try:
        r = requests.get(url, headers=headers, timeout=30)
        payload = r.json() if r.content else {}
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    if r.status_code >= 400 or payload.get("status") is not True:
        # Store failure for audit
        upsert_payment(reference, {"reference": reference, "status": "failed", "raw": payload})
        return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": payload}), 400

    d = payload.get("data") or {}
    paystack_status = str(d.get("status", "")).lower()  # success|failed|abandoned
    paid = (paystack_status == "success")

    amount_kobo = d.get("amount")
    currency = d.get("currency")
    gateway_response = d.get("gateway_response")

    customer = d.get("customer") or {}
    customer_email = customer.get("email")

    metadata = d.get("metadata") or {}
    wa_phone = str(metadata.get("wa_phone", "")).strip()
    plan = str(metadata.get("plan", "")).strip().lower()

    # Update payment record
    upsert_payment(reference, {
        "reference": reference,
        "wa_phone": wa_phone or None,
        "email": customer_email or None,
        "plan": plan or None,
        "amount_kobo": amount_kobo,
        "currency": currency,
        "status": paystack_status,
        "gateway_response": gateway_response,
        "raw": d,
    })

    expires_at = None
    if paid:
        # Auto WhatsApp unlock after payment = activate subscription
        if wa_phone and plan in PLAN_DURATION_DAYS:
            expires_at = activate_subscription(wa_phone, plan)

        # Email receipt (optional)
        try:
            send_email_receipt(
                to_email=customer_email or "",
                subject="Naija Tax Guide — Payment Receipt",
                body=(
                    f"Payment verified successfully.\n\n"
                    f"Reference: {reference}\n"
                    f"Plan: {plan}\n"
                    f"WhatsApp: {wa_phone}\n"
                    f"Amount (kobo): {amount_kobo}\n"
                    f"Status: {paystack_status}\n"
                    f"Expires at: {expires_at or 'N/A'}\n\n"
                    f"If you have any issues, contact support: info@thecre8hub.com\n"
                ),
            )
        except Exception as e:
            logging.warning("Email receipt failed: %s", str(e))

    return jsonify({
        "ok": True,
        "paid": paid,
        "reference": reference,
        "status": paystack_status,
        "currency": currency,
        "amount_kobo": amount_kobo,
        "gateway_response": gateway_response,
        "customer_email": customer_email,
        "wa_phone": wa_phone,
        "plan": plan,
        "expires_at": expires_at,
    }), 200

# ------------------------------------------------------------
# PAYSTACK: WEBHOOK (authoritative source)
# Set Paystack webhook URL to: https://YOUR_BACKEND/paystack/webhook
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

    evt = request.get_json(silent=True) or {}
    event_type = str(evt.get("event", "")).strip()
    data = evt.get("data") or {}

    reference = str(data.get("reference", "")).strip()
    status = str(data.get("status", "")).lower()
    amount_kobo = data.get("amount")
    currency = data.get("currency")
    gateway_response = data.get("gateway_response")

    customer = data.get("customer") or {}
    customer_email = customer.get("email")

    metadata = data.get("metadata") or {}
    wa_phone = str(metadata.get("wa_phone", "")).strip()
    plan = str(metadata.get("plan", "")).strip().lower()

    # Always store webhook payload (idempotent on reference)
    if reference:
        upsert_payment(reference, {
            "reference": reference,
            "wa_phone": wa_phone or None,
            "email": customer_email or None,
            "plan": plan or None,
            "amount_kobo": amount_kobo,
            "currency": currency,
            "status": status or event_type or "webhook",
            "gateway_response": gateway_response,
            "raw": data,
        })

    # On success, activate subscription
    if event_type in ("charge.success", "transaction.success") and status == "success":
        if wa_phone and plan in PLAN_DURATION_DAYS:
            expires_at = activate_subscription(wa_phone, plan)
            logging.info("Activated subscription via webhook wa_phone=%s plan=%s expires_at=%s", wa_phone, plan, expires_at)

    return "ok", 200

# ------------------------------------------------------------
# CRON: Expire subscriptions (call this daily via scheduler)
# ------------------------------------------------------------
@app.post("/cron/expire_subscriptions")
def cron_expire_subscriptions():
    if not admin_required():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    sb = get_supabase()
    now = iso(now_utc())

    # Find active subs that have expired
    resp = sb.table("user_subscriptions").select("wa_phone,expires_at,status").eq("status", "active").execute()
    rows = resp.data or []

    expired = 0
    for r in rows:
        exp = r.get("expires_at")
        if exp and exp < now:
            sb.table("user_subscriptions").update({
                "status": "expired",
                "updated_at": now,
            }).eq("wa_phone", r["wa_phone"]).execute()
            expired += 1

    return jsonify({"ok": True, "expired_marked": expired}), 200

# ------------------------------------------------------------
# ADMIN APIs (for Admin Dashboard)
# ------------------------------------------------------------
@app.get("/admin/subscriptions")
def admin_subscriptions():
    if not admin_required():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    sb = get_supabase()
    resp = sb.table("user_subscriptions").select("*").order("updated_at", desc=True).limit(200).execute()
    return jsonify({"ok": True, "data": resp.data or []}), 200

@app.get("/admin/payments")
def admin_payments():
    if not admin_required():
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    sb = get_supabase()
    resp = sb.table("paystack_payments").select("*").order("updated_at", desc=True).limit(200).execute()
    return jsonify({"ok": True, "data": resp.data or []}), 200
