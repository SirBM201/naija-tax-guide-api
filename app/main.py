import os
import json
import hmac
import hashlib
import logging
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

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

# WhatsApp Cloud API
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "").strip()  # Permanent token from Meta
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()

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

def admin_required() -> bool:
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

def activate_subscription(wa_phone: str, plan: str, email: Optional[str] = None) -> str:
    sb = get_supabase()
    days = PLAN_DURATION_DAYS.get(plan, 30)
    expires_at = now_utc() + timedelta(days=days)

    # Note: keep wa_phone as your primary key for WhatsApp-based access.
    # You can later expand to user_id / multi-channel identity mapping.
    record = {
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": iso(expires_at),
        "updated_at": iso(now_utc()),
    }
    if email:
        record["email"] = email

    sb.table("user_subscriptions").upsert(record, on_conflict="wa_phone").execute()
    return iso(expires_at)

def get_subscription_status_for_wa(wa_phone: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Returns (is_active, row)
    Active means status=active AND expires_at > now
    """
    sb = get_supabase()
    resp = sb.table("user_subscriptions").select("*").eq("wa_phone", wa_phone).limit(1).execute()
    rows = resp.data or []
    if not rows:
        return False, None

    row = rows[0]
    status = str(row.get("status", "")).lower()
    exp = row.get("expires_at")

    if status != "active" or not exp:
        return False, row

    # ISO strings compare safely if both are ISO UTC; but we’ll parse defensively
    try:
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
    except Exception:
        return False, row

    if exp_dt <= now_utc():
        return False, row

    return True, row

def whatsapp_send_text(to_phone: str, text: str) -> bool:
    """
    Sends a WhatsApp text message via Cloud API.
    to_phone must be in international format (e.g. 23480xxxxxxx).
    """
    if not (WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID):
        logging.warning("WhatsApp env missing (WHATSAPP_TOKEN / WHATSAPP_PHONE_NUMBER_ID). Cannot send.")
        return False

    url = f"https://graph.facebook.com/v20.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        ok = (r.status_code < 300)
        if not ok:
            logging.warning("WhatsApp send failed: %s %s", r.status_code, r.text[:500])
        return ok
    except Exception as e:
        logging.warning("WhatsApp send exception: %s", str(e))
        return False

def locked_message(wa_phone: str) -> str:
    """
    Message shown to non-subscribed or expired users.
    """
    pricing_url = "https://thecre8hub.com/pricing"
    return (
        "Your subscription is not active.\n\n"
        "To continue using Naija Tax Guide, please subscribe here:\n"
        f"{pricing_url}\n\n"
        f"Your WhatsApp number: {wa_phone}\n"
        "After payment, your access will unlock automatically."
    )

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

# ============================================================
# WHATSAPP WEBHOOK
# Callback URL MUST be: https://YOUR_BACKEND/webhook
# ============================================================

@app.get("/webhook")
def whatsapp_webhook_verify():
    """
    Meta verification:
    GET /webhook?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200

    return "Forbidden", 403


def require_active_subscription_for_whatsapp(wa_phone: str) -> bool:
    """
    THIS IS THE 'MIDDLEWARE' YOU ASKED FOR:
    Call this at the start of every inbound WhatsApp message.
    """
    if not wa_phone:
        return False

    is_active, _row = get_subscription_status_for_wa(wa_phone)
    return is_active


@app.post("/webhook")
def whatsapp_webhook_receive():
    """
    Receives incoming WhatsApp messages from Meta.
    We enforce subscription BEFORE processing user message.
    """
    payload = request.get_json(silent=True) or {}

    try:
        entry = (payload.get("entry") or [])[0] if isinstance(payload.get("entry"), list) else {}
        changes = (entry.get("changes") or [])[0] if isinstance(entry.get("changes"), list) else {}
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            # Some webhook calls are status updates; acknowledge quickly
            return "OK", 200

        msg = messages[0]
        from_phone = str(msg.get("from", "")).strip()  # user's WhatsApp number
        msg_type = str(msg.get("type", "")).strip()

        # -------------------------
        # SUBSCRIPTION ENFORCEMENT
        # -------------------------
        if not require_active_subscription_for_whatsapp(from_phone):
            # Reply and stop processing
            whatsapp_send_text(from_phone, locked_message(from_phone))
            return "OK", 200

        # -------------------------
        # If active: proceed normally
        # For now, just echo, but you can plug your AI logic here.
        # -------------------------
        user_text = ""
        if msg_type == "text":
            user_text = (msg.get("text") or {}).get("body") or ""

        if user_text:
            # TODO: replace with your Tax AI logic
            reply = f"Received: {user_text}\n\n(Active subscription confirmed ✅)"
            whatsapp_send_text(from_phone, reply)

        return "OK", 200

    except Exception as e:
        logging.exception("WhatsApp webhook error: %s", str(e))
        # Always return 200 to avoid repeated retries spiraling
        return "OK", 200

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

    if not callback_url:
        callback_url = "http://localhost:3000/payment-success"

    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

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
        upsert_payment(reference, {"reference": reference, "status": "failed", "raw": payload})
        return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": payload}), 400

    d = payload.get("data") or {}
    paystack_status = str(d.get("status", "")).lower()
    paid = (paystack_status == "success")

    amount_kobo = d.get("amount")
    currency = d.get("currency")
    gateway_response = d.get("gateway_response")

    customer = d.get("customer") or {}
    customer_email = customer.get("email")

    metadata = d.get("metadata") or {}
    wa_phone = str(metadata.get("wa_phone", "")).strip()
    plan = str(metadata.get("plan", "")).strip().lower()

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
        if wa_phone and plan in PLAN_DURATION_DAYS:
            expires_at = activate_subscription(wa_phone, plan, email=customer_email)

            # Optional: notify user instantly on WhatsApp
            whatsapp_send_text(
                wa_phone,
                f"Payment received ✅\nPlan: {plan}\nAccess unlocked.\nExpires: {expires_at}"
            )

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
# PAYSTACK: WEBHOOK (authoritative)
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

    if event_type in ("charge.success", "transaction.success") and status == "success":
        if wa_phone and plan in PLAN_DURATION_DAYS:
            expires_at = activate_subscription(wa_phone, plan, email=customer_email)
            logging.info("Activated subscription via webhook wa_phone=%s plan=%s expires_at=%s", wa_phone, plan, expires_at)

            # Optional WhatsApp push:
            whatsapp_send_text(
                wa_phone,
                f"Payment confirmed ✅\nPlan: {plan}\nAccess unlocked.\nExpires: {expires_at}"
            )

    return "ok", 200

# ------------------------------------------------------------
# CRON: Expire subscriptions (call daily via scheduler)
# ------------------------------------------------------------
@app.post("/cron/expire_subscriptions")
def cron_expire_subscriptions():
    if not admin_required():
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    sb = get_supabase()
    now = now_utc()

    resp = sb.table("user_subscriptions").select("wa_phone,expires_at,status").eq("status", "active").execute()
    rows = resp.data or []

    expired = 0
    for r in rows:
        exp = r.get("expires_at")
        if not exp:
            continue
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        except Exception:
            continue

        if exp_dt <= now:
            sb.table("user_subscriptions").update({
                "status": "expired",
                "updated_at": iso(now_utc()),
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
