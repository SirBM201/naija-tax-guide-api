# app.py
import os
import re
import uuid
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

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
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")

APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

# Admin key for protected admin/cron endpoints
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

# SMTP (for email receipts / test)
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", "").strip()  # e.g. info@thecre8hub.com

# CORS allowed origins: comma-separated
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
    return re.sub(r"\D", "", (wa_phone or "").strip())

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
# Admin security
# ------------------------------------------------------------
def require_admin(req) -> bool:
    if not ADMIN_API_KEY:
        return False
    key = (req.headers.get("x-admin-key") or "").strip()
    return key == ADMIN_API_KEY


# ------------------------------------------------------------
# Email
# ------------------------------------------------------------
def smtp_ready() -> Tuple[bool, str]:
    if not (SMTP_HOST and SMTP_PORT and SMTP_USER and SMTP_PASS and SMTP_FROM):
        return False, "SMTP env vars missing. Need SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM"
    return True, "ok"

def send_email(to_email: str, subject: str, html_body: str) -> Tuple[bool, str]:
    ok, msg = smtp_ready()
    if not ok:
        return False, msg

    to_email = (to_email or "").strip()
    if not to_email or "@" not in to_email:
        return False, "Invalid to_email"

    m = MIMEMultipart("alternative")
    m["From"] = SMTP_FROM
    m["To"] = to_email
    m["Subject"] = subject

    m.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, [to_email], m.as_string())
        return True, "sent"
    except Exception as e:
        logging.exception("SMTP send failed")
        return False, str(e)

def receipt_html(app_name: str, wa_phone: str, plan: str, amount_kobo: int, currency: str, reference: str) -> str:
    amount = f"{amount_kobo/100:,.2f}"
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:640px;margin:auto">
      <h2>{app_name} – Payment Receipt</h2>
      <p>Thank you. Your subscription payment was successful.</p>
      <table style="border-collapse:collapse;width:100%">
        <tr><td style="padding:8px;border:1px solid #ddd"><b>WhatsApp</b></td><td style="padding:8px;border:1px solid #ddd">{wa_phone}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd"><b>Plan</b></td><td style="padding:8px;border:1px solid #ddd">{plan}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd"><b>Amount</b></td><td style="padding:8px;border:1px solid #ddd">{currency} {amount}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd"><b>Reference</b></td><td style="padding:8px;border:1px solid #ddd">{reference}</td></tr>
        <tr><td style="padding:8px;border:1px solid #ddd"><b>Date</b></td><td style="padding:8px;border:1px solid #ddd">{iso(now_utc())}</td></tr>
      </table>
      <p style="margin-top:16px">Support: {SMTP_FROM}</p>
    </div>
    """


# ------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------
def record_paystack_event(event_id: str, event_type: str, reference: Optional[str], payload: Dict[str, Any]) -> bool:
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

def upsert_payment(
    reference: str,
    wa_phone: str,
    plan: str,
    amount_kobo: int,
    currency: str,
    status: str,
    paid_at_iso: Optional[str],
    raw_event: Dict[str, Any],
) -> None:
    """
    Matches your existing payments columns (from screenshot):
      reference (text), wa_phone (text), provider (text), plan (text),
      amount_kobo (int), currency (text), status (text),
      created_at (timestamptz), paid_at (timestamptz), raw_event (jsonb)
    """
    reference = (reference or "").strip()
    if not reference:
        return

    row = {
        "reference": reference,
        "wa_phone": normalize_wa_phone(wa_phone),
        "provider": "paystack",
        "plan": (plan or "").lower(),
        "amount_kobo": int(amount_kobo or 0),
        "currency": (currency or CURRENCY),
        "status": (status or "").lower(),
        "created_at": iso(now_utc()),
        "paid_at": paid_at_iso,
        "raw_event": raw_event or {},
    }

    # If you want created_at to be the first time only,
    # keep it as now for simplicity; reference acts as idempotency.
    sb.table("payments").upsert(row, on_conflict="reference").execute()

def expire_due_subscriptions() -> Dict[str, Any]:
    summary: Dict[str, Any] = {"checked": 0, "expired": 0, "errors": 0}
    try:
        res = (
            sb.table("user_subscriptions")
            .select("wa_phone, expires_at, status")
            .eq("status", "active")
            .limit(5000)
            .execute()
        )

        rows = res.data or []
        summary["checked"] = len(rows)

        to_expire = []
        for r in rows:
            exp = r.get("expires_at")
            if not exp:
                continue
            try:
                exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                if exp_dt < now_utc():
                    to_expire.append(r.get("wa_phone"))
            except Exception:
                summary["errors"] += 1

        if not to_expire:
            return summary

        now_iso = iso(now_utc())
        BATCH = 200
        for i in range(0, len(to_expire), BATCH):
            batch = to_expire[i:i+BATCH]
            sb.table("user_subscriptions").update({
                "status": "expired",
                "updated_at": now_iso
            }).in_("wa_phone", batch).execute()

        summary["expired"] = len(to_expire)
        return summary

    except Exception as e:
        logging.exception("expire_due_subscriptions failed")
        summary["errors"] += 1
        summary["error_message"] = str(e)
        return summary


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})


# ---------------------------
# Cron: Expire subscriptions
# ---------------------------
@app.get("/cron/expire_subscriptions")
def cron_expire_subscriptions():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    summary = expire_due_subscriptions()
    return jsonify({"ok": True, "summary": summary}), 200


# ---------------------------
# Admin: subscriptions
# ---------------------------
@app.get("/admin/subscriptions")
def admin_subscriptions():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    res = (
        sb.table("user_subscriptions")
        .select("wa_phone, plan, status, expires_at, updated_at")
        .order("updated_at", desc=True)
        .limit(2000)
        .execute()
    )
    return jsonify(res.data or []), 200


# ---------------------------
# Admin: payments
# ---------------------------
@app.get("/admin/payments")
def admin_payments():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    res = (
        sb.table("payments")
        .select("reference, wa_phone, provider, plan, amount_kobo, currency, status, created_at, paid_at")
        .order("created_at", desc=True)
        .limit(2000)
        .execute()
    )
    return jsonify(res.data or []), 200


# ---------------------------
# Admin: test email (THIS FIXES YOUR 404)
# ---------------------------
@app.post("/admin/test_email")
def admin_test_email():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    to_email = safe_text(data.get("to_email"))
    wa_phone = normalize_wa_phone(safe_text(data.get("wa_phone")))
    plan = safe_text(data.get("plan")).lower() or "monthly"

    amount = int(PLAN_PRICES.get(plan, PLAN_PRICES["monthly"]))
    subject = f"{os.getenv('APP_NAME', 'Naija Tax Guide')} – Test Receipt"
    html = receipt_html(os.getenv("APP_NAME", "Naija Tax Guide"), wa_phone or "234xxxxxxxxxx", plan, amount, CURRENCY, f"test_{uuid.uuid4().hex[:10]}")

    ok, msg = send_email(to_email, subject, html)
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 500)


# ---------------------------
# Paystack Initialize
# ---------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
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
            "receipt_email": email or None,
        }
    }

    if APP_BASE_URL:
        payload["callback_url"] = f"{APP_BASE_URL}/payment-success?reference={reference}"

    try:
        r = requests.post(PAYSTACK_INIT_URL, headers=paystack_headers(), json=payload, timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            logging.error("Paystack init failed: %s %s", r.status_code, resp)
            return jsonify({"status": "error", "error": "paystack_init_failed", "detail": resp}), 502

        auth_url = resp["data"]["authorization_url"]

        # Log an initial payment row (pending)
        upsert_payment(
            reference=reference,
            wa_phone=wa_phone,
            plan=plan,
            amount_kobo=amount_kobo,
            currency=CURRENCY,
            status="pending",
            paid_at_iso=None,
            raw_event={"source": "initialize", "payload": payload, "paystack": resp},
        )

        return jsonify({"status": "ok", "authorization_url": auth_url, "reference": reference}), 200

    except Exception as e:
        logging.exception("Initialize exception")
        return jsonify({"status": "error", "error": str(e)}), 500


# ---------------------------
# Paystack Verify
# ---------------------------
@app.post("/paystack/verify")
def paystack_verify():
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
        status = (d.get("status") or "").lower()
        paid = status == "success"

        metadata = d.get("metadata", {}) or {}
        wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
        plan = str(metadata.get("plan") or "").lower()
        amount_kobo = int(d.get("amount") or 0)
        currency = str(d.get("currency") or CURRENCY)
        paid_at_val = d.get("paid_at")
        paid_at_iso = None
        if paid_at_val:
            paid_at_iso = str(paid_at_val).replace("Z", "+00:00")

        # Log/update payment
        upsert_payment(
            reference=reference,
            wa_phone=wa_phone,
            plan=plan,
            amount_kobo=amount_kobo,
            currency=currency,
            status=status,
            paid_at_iso=paid_at_iso,
            raw_event={"source": "verify", "paystack": resp},
        )

        if paid and wa_phone and plan in PLAN_PRICES:
            activate_user_subscription(wa_phone, plan)

            # Optional receipt email
            receipt_to = (metadata.get("receipt_email") or d.get("customer", {}).get("email") or "").strip()
            if receipt_to:
                subject = f"{os.getenv('APP_NAME', 'Naija Tax Guide')} – Receipt ({plan})"
                html = receipt_html(os.getenv("APP_NAME", "Naija Tax Guide"), wa_phone, plan, amount_kobo, currency, reference)
                send_email(receipt_to, subject, html)

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

    # Dedup record (safe even if duplicate)
    record_paystack_event(event_id, event_type, reference, payload)

    # Update payments table
    status = str(data.get("status") or "").lower()
    amount_kobo = int(data.get("amount") or 0)
    currency = str(data.get("currency") or CURRENCY)
    metadata = data.get("metadata", {}) or {}
    wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
    plan = str(metadata.get("plan") or "").lower()
    paid_at_val = data.get("paid_at")
    paid_at_iso = None
    if paid_at_val:
        paid_at_iso = str(paid_at_val).replace("Z", "+00:00")

    upsert_payment(
        reference=reference,
        wa_phone=wa_phone,
        plan=plan,
        amount_kobo=amount_kobo,
        currency=currency,
        status=status or event_type,
        paid_at_iso=paid_at_iso,
        raw_event={"source": "webhook", "event": event_type, "payload": payload},
    )

    if event_type == "charge.success":
        purpose = metadata.get("purpose")
        if purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
            activate_user_subscription(wa_phone, plan)

            receipt_to = (metadata.get("receipt_email") or data.get("customer", {}).get("email") or "").strip()
            if receipt_to:
                subject = f"{os.getenv('APP_NAME', 'Naija Tax Guide')} – Receipt ({plan})"
                html = receipt_html(os.getenv("APP_NAME", "Naija Tax Guide"), wa_phone, plan, amount_kobo, currency, reference)
                send_email(receipt_to, subject, html)

    return "OK", 200
