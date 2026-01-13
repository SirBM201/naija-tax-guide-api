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
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")

APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

# Admin key for protected admin/cron endpoints
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

# -----------------------------
# SMTP (Email receipts)
# -----------------------------
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
SMTP_FROM_NAME = os.getenv("SMTP_FROM_NAME", "Naija Tax Guide").strip()
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USERNAME).strip()

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
# Admin Security Helpers
# ------------------------------------------------------------
def require_admin(req) -> bool:
    if not ADMIN_API_KEY:
        return False
    key = (req.headers.get("x-admin-key") or "").strip()
    return key == ADMIN_API_KEY

# ------------------------------------------------------------
# SMTP / Email helpers
# ------------------------------------------------------------
def smtp_ready() -> bool:
    return all([SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM_EMAIL])

def send_email(to_email: str, subject: str, html_body: str) -> None:
    if not smtp_ready():
        raise RuntimeError("SMTP not configured. Set SMTP_HOST/PORT/USERNAME/PASSWORD/FROM_EMAIL.")

    msg = MIMEMultipart("alternative")
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_FROM_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(html_body, "html"))

    server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
    try:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_FROM_EMAIL, [to_email], msg.as_string())
    finally:
        try:
            server.quit()
        except Exception:
            pass

def format_naira_from_kobo(amount_kobo: int) -> str:
    try:
        return f"₦{(int(amount_kobo) / 100):,.2f}"
    except Exception:
        return "₦0.00"

def receipt_email_html(
    wa_phone: str,
    plan: str,
    reference: str,
    amount_kobo: int,
    status: str,
    paid_at_iso: Optional[str],
) -> str:
    amount = format_naira_from_kobo(amount_kobo)
    paid_at = paid_at_iso or "N/A"
    plan_label = (plan or "").capitalize()

    return f"""
    <div style="font-family: Arial, sans-serif; max-width: 640px; margin: 0 auto; padding: 16px;">
      <h2 style="margin:0 0 12px 0;">Naija Tax Guide — Payment Receipt</h2>
      <p style="margin:0 0 12px 0;">Thank you for your subscription.</p>

      <table style="width:100%; border-collapse: collapse; margin-top: 12px;">
        <tr><td style="padding:10px; border:1px solid #ddd;"><strong>Reference</strong></td>
            <td style="padding:10px; border:1px solid #ddd;">{reference}</td></tr>
        <tr><td style="padding:10px; border:1px solid #ddd;"><strong>WhatsApp Number</strong></td>
            <td style="padding:10px; border:1px solid #ddd;">{wa_phone}</td></tr>
        <tr><td style="padding:10px; border:1px solid #ddd;"><strong>Plan</strong></td>
            <td style="padding:10px; border:1px solid #ddd;">{plan_label}</td></tr>
        <tr><td style="padding:10px; border:1px solid #ddd;"><strong>Amount</strong></td>
            <td style="padding:10px; border:1px solid #ddd;">{amount}</td></tr>
        <tr><td style="padding:10px; border:1px solid #ddd;"><strong>Status</strong></td>
            <td style="padding:10px; border:1px solid #ddd;">{status}</td></tr>
        <tr><td style="padding:10px; border:1px solid #ddd;"><strong>Paid At</strong></td>
            <td style="padding:10px; border:1px solid #ddd;">{paid_at}</td></tr>
      </table>

      <p style="margin-top: 18px;">Need help? Contact us at <strong>{SMTP_FROM_EMAIL}</strong>.</p>
      <p style="color:#777; font-size: 12px; margin-top: 22px;">
        Naija Tax Guide • Automated receipt
      </p>
    </div>
    """

def send_payment_receipt_email(
    to_email: str,
    wa_phone: str,
    plan: str,
    reference: str,
    amount_kobo: int,
    status: str,
    paid_at_iso: Optional[str],
) -> None:
    subject = f"Naija Tax Guide Receipt — {reference}"
    html = receipt_email_html(
        wa_phone=wa_phone,
        plan=plan,
        reference=reference,
        amount_kobo=amount_kobo,
        status=status,
        paid_at_iso=paid_at_iso
    )
    send_email(to_email=to_email, subject=subject, html_body=html)

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

# ------------------------------------------------------------
# Subscription Expiry Worker (Cron)
# ------------------------------------------------------------
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

@app.get("/cron/expire_subscriptions")
def cron_expire_subscriptions():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    summary = expire_due_subscriptions()
    return jsonify({"ok": True, "summary": summary}), 200

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
# Admin: test email
# ---------------------------
@app.post("/admin/test_email")
def admin_test_email():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    to_email = (data.get("to_email") or "").strip()
    wa_phone = normalize_wa_phone(str(data.get("wa_phone") or "2340000000000"))
    plan = (data.get("plan") or "monthly").strip().lower()
    reference = (data.get("reference") or f"test_{uuid.uuid4().hex[:10]}").strip()

    if not to_email or "@" not in to_email:
        return jsonify({"ok": False, "error": "to_email is required"}), 400

    try:
        send_payment_receipt_email(
            to_email=to_email,
            wa_phone=wa_phone,
            plan=plan,
            reference=reference,
            amount_kobo=PLAN_PRICES.get(plan, 300000),
            status="success",
            paid_at_iso=iso(now_utc())
        )
        return jsonify({"ok": True, "message": "Test email sent"}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

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

    safe_user_email = safe_email(email, wa_phone)

    payload = {
        "email": safe_user_email,
        "amount": amount_kobo,
        "currency": CURRENCY,
        "reference": reference,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
            "email": safe_user_email,  # IMPORTANT: so webhook can fallback to email
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

        # Try to get customer email from Paystack verify response
        customer = d.get("customer", {}) or {}
        customer_email = (customer.get("email") or "").strip()
        if not customer_email:
            customer_email = (metadata.get("email") or "").strip()

        amount_kobo = int(d.get("amount") or 0)
        paid_at_iso = (d.get("paid_at") or "").strip() or (iso(now_utc()) if paid else None)

        if paid and wa_phone and plan in PLAN_PRICES:
            activate_user_subscription(wa_phone, plan)

            # Optional: send receipt here as a fallback (webhook is primary)
            if customer_email and "@" in customer_email and smtp_ready():
                try:
                    send_payment_receipt_email(
                        to_email=customer_email,
                        wa_phone=wa_phone,
                        plan=plan,
                        reference=reference,
                        amount_kobo=amount_kobo,
                        status="success",
                        paid_at_iso=paid_at_iso
                    )
                except Exception as e:
                    logging.warning("Receipt email (verify) failed: %s", str(e))

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

    record_paystack_event(event_id, event_type, reference, payload)

    if event_type == "charge.success":
        metadata = data.get("metadata", {}) or {}
        purpose = metadata.get("purpose")
        wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
        plan = str(metadata.get("plan") or "").lower()

        customer = data.get("customer", {}) or {}
        customer_email = (customer.get("email") or "").strip()
        if not customer_email:
            customer_email = (metadata.get("email") or "").strip()

        amount_kobo = int(data.get("amount") or 0)
        paid_at_iso = (data.get("paid_at") or "").strip() or iso(now_utc())

        if purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
            activate_user_subscription(wa_phone, plan)

            if customer_email and "@" in customer_email and smtp_ready():
                try:
                    send_payment_receipt_email(
                        to_email=customer_email,
                        wa_phone=wa_phone,
                        plan=plan,
                        reference=reference,
                        amount_kobo=amount_kobo,
                        status="success",
                        paid_at_iso=paid_at_iso
                    )
                    logging.info("Receipt email sent to %s for %s", customer_email, reference)
                except Exception as e:
                    logging.warning("Receipt email (webhook) failed: %s", str(e))

    return "OK", 200

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
