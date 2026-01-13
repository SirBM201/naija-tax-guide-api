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
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "").strip()
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

    try:
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
    except Exception:
        return False, row

    if exp_dt <= now_utc():
        return False, row

    return True, row

def whatsapp_send_text(to_phone: str, text: str) -> bool:
    if not (WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID):
        logging.warning("WhatsApp env missing: WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID")
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
        if r.status_code >= 300:
            logging.warning("WhatsApp send failed: %s %s", r.status_code, r.text[:500])
            return False
        return True
    except Exception as e:
        logging.warning("WhatsApp send exception: %s", str(e))
        return False

def locked_message(wa_phone: str) -> str:
    pricing_url = "https://thecre8hub.com/pricing"
    return (
        "Access Locked ❌\n\n"
        "Your Naija Tax Guide subscription is not active.\n\n"
        f"Subscribe here to unlock instantly:\n{pricing_url}\n\n"
        f"WhatsApp: {wa_phone}\n\n"
        "If you already paid and still locked, contact: info@thecre8hub.com"
    )

def require_active_subscription_for_whatsapp(wa_phone: str) -> bool:
    # Middleware: enforce on EVERY WhatsApp inbound message
    if not wa_phone:
        return False
    active, _ = get_subscription_status_for_wa(wa_phone)
    return active

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

@app.get("/")
def home():
    return jsonify({"ok": True, "service": "naija-tax-guide-api"})

@app.get("/health")
def health():
    return jsonify({"ok": True})

# ============================================================
# WHATSAPP WEBHOOK
# Callback URL: https://YOUR_BACKEND/webhook
# ============================================================

@app.get("/webhook")
def whatsapp_webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN and challenge:
        return challenge, 200
    return "Forbidden", 403

@app.post("/webhook")
def whatsapp_webhook_receive():
    payload = request.get_json(silent=True) or {}

    # Helpful logs for debugging (safe)
    logging.info("WA webhook received keys=%s", list(payload.keys()))

    try:
        entry_list = payload.get("entry") or []
        if not entry_list:
            return "OK", 200

        entry = entry_list[0] or {}
        changes_list = entry.get("changes") or []
        if not changes_list:
            return "OK", 200

        value = (changes_list[0] or {}).get("value") or {}

        # Status updates (delivery/read/etc) contain "statuses", not "messages"
        if value.get("statuses"):
            return "OK", 200

        messages = value.get("messages") or []
        if not messages:
            return "OK", 200

        msg = messages[0] or {}
        from_phone = str(msg.get("from", "")).strip()
        msg_type = str(msg.get("type", "")).strip()

        # Enforce subscription
        if not require_active_subscription_for_whatsapp(from_phone):
            whatsapp_send_text(from_phone, locked_message(from_phone))
            return "OK", 200

        # Active -> process
        user_text = ""
        if msg_type == "text":
            user_text = ((msg.get("text") or {}).get("body")) or ""

        # TODO: Replace this with your AI tax logic
        if user_text:
            reply = f"✅ Subscription active.\n\nYou said: {user_text}\n\n(Next: connect AI response here.)"
            whatsapp_send_text(from_phone, reply)

        return "OK", 200

    except Exception as e:
        logging.exception("WhatsApp webhook processing error: %s", str(e))
        return "OK", 200

# ------------------------------------------------------------
# PAYSTACK: INITIALIZE
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
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}

    payload = {
        "email": email,
        "amount": amount_kobo,
        "callback_url": callback_url,
        "metadata": {"wa_phone": wa_phone, "plan": plan, "product": "naija-tax-guide"},
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

    upsert_payment(reference, {
        "reference": reference,
        "wa_phone": wa_phone,
        "email": email,
        "plan": plan,
        "amount_kobo": amount_kobo,
        "currency": "NGN",
        "status": "initialized",
        "gateway_response": None,
        "raw": d,
    })

    return jsonify({
        "ok": True,
        "plan": plan,
        "wa_phone": wa_phone,
        "amount": amount_ngn,
        "reference": reference,
        "authorization_url": d.get("authorization_url"),
        "access_code": d.get("access_code"),
    }), 200

# ------------------------------------------------------------
# PAYSTACK: VERIFY
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
        "amount_kobo": d.get("amount"),
        "currency": d.get("currency"),
        "status": paystack_status,
        "gateway_response": d.get("gateway_response"),
        "raw": d,
    })

    expires_at = None
    if paid and wa_phone and plan in PLAN_DURATION_DAYS:
        expires_at = activate_subscription(wa_phone, plan, email=customer_email)

        # WhatsApp unlock notification
        whatsapp_send_text(wa_phone, f"Payment received ✅\nPlan: {plan}\nUnlocked.\nExpires: {expires_at}")

        # Email receipt (optional)
        try:
            send_email_receipt(
                to_email=customer_email or "",
                subject="Naija Tax Guide — Payment Receipt",
                body=(
                    f"Payment verified successfully.\n\n"
                    f"Reference: {reference}\nPlan: {plan}\nWhatsApp: {wa_phone}\n"
                    f"Status: {paystack_status}\nExpires: {expires_at}\n\n"
                    "Support: info@thecre8hub.com\n"
                ),
            )
        except Exception as e:
            logging.warning("Email receipt failed: %s", str(e))

    return jsonify({
        "ok": True,
        "paid": paid,
        "reference": reference,
        "status": paystack_status,
        "customer_email": customer_email,
        "wa_phone": wa_phone,
        "plan": plan,
        "expires_at": expires_at,
    }), 200

# ------------------------------------------------------------
# PAYSTACK: WEBHOOK
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
            "amount_kobo": data.get("amount"),
            "currency": data.get("currency"),
            "status": status or event_type or "webhook",
            "gateway_response": data.get("gateway_response"),
            "raw": data,
        })

    if event_type in ("charge.success", "transaction.success") and status == "success":
        if wa_phone and plan in PLAN_DURATION_DAYS:
            expires_at = activate_subscription(wa_phone, plan, email=customer_email)
            whatsapp_send_text(wa_phone, f"Payment confirmed ✅\nPlan: {plan}\nUnlocked.\nExpires: {expires_at}")

    return "ok", 200

# ------------------------------------------------------------
# CRON: Expire subscriptions (daily)
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
# ADMIN APIs
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
