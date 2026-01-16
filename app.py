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
    # store digits-only in DB (matches your screenshots)
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
    Requires paystack_events.event_id UNIQUE (you already created the unique index)
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
    """
    Your payments table (from screenshots) includes:
      reference, wa_phone, provider, plan, amount_kobo, currency, status, created_at, paid_at, raw_event, email
    reference is UNIQUE (already created)
    """
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
        .select("reference, wa_phone, provider, plan, amount_kobo, currency, status, created_at, paid_at, email")
        .order("created_at", desc=True)
        .limit(2000)
        .execute()
    )
    return jsonify(res.data or []), 200

@app.post("/admin/test_email")
def admin_test_email():
    if not require_admin(request):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    to_email = safe_text(data.get("to_email"))

    if not to_email or "@" not in to_email:
        return jsonify({"ok": False, "error": "to_email required"}), 400

    subject = "Test Email – Naija Tax Guide"
    html = f"""
    <div style="font-family:Arial,sans-serif">
      <h2>Test Email Successful</h2>
      <p>This confirms SMTP is working.</p>
      <p><b>Time (UTC):</b> {iso(now_utc())}</p>
    </div>
    """

    try:
        send_email(to_email, subject, html)
        return jsonify({"ok": True, "message": "Email sent"}), 200
    except Exception as e:
        logging.exception("test_email failed")
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

    if APP_BASE_URL:
        payload["callback_url"] = f"{APP_BASE_URL}/payment-success?reference={reference}"

    # Pre-create payment row (non-fatal if fails)
    try:
        upsert_payment_row(
            reference=reference,
            wa_phone=wa_phone,
            plan=plan,
            amount_kobo=amount_kobo,
            currency=CURRENCY,
            status="initialized",
            provider="paystack",
            paid_at=None,
            raw_event={"init_payload": payload},
            email=payload["email"],
        )
    except Exception:
        logging.exception("Failed to precreate payment row (non-fatal)")

    try:
        r = requests.post(PAYSTACK_INIT_URL, headers=paystack_headers(), json=payload, timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            logging.error("Paystack init failed: %s %s", r.status_code, resp)
            try:
                upsert_payment_row(
                    reference=reference,
                    wa_phone=wa_phone,
                    plan=plan,
                    amount_kobo=amount_kobo,
                    currency=CURRENCY,
                    status="init_failed",
                    provider="paystack",
                    raw_event={"init_failed": resp},
                    email=payload["email"],
                )
            except Exception:
                pass
            return jsonify({"status": "error", "error": "paystack_init_failed", "detail": resp}), 502

        auth_url = resp["data"]["authorization_url"]

        try:
            upsert_payment_row(
                reference=reference,
                wa_phone=wa_phone,
                plan=plan,
                amount_kobo=amount_kobo,
                currency=CURRENCY,
                status="pending",
                provider="paystack",
                raw_event={"init_response": resp},
                email=payload["email"],
            )
        except Exception:
            pass

        return jsonify({"status": "ok", "authorization_url": auth_url, "reference": reference}), 200

    except Exception as e:
        logging.exception("Initialize exception")
        return jsonify({"status": "error", "error": str(e)}), 500

# ---------------------------
# Paystack Verify (used by /payment-success page)
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

        amount_kobo = d.get("amount")
        currency = d.get("currency") or CURRENCY

        metadata = d.get("metadata", {}) or {}
        wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
        plan = str(metadata.get("plan") or "").lower()
        purpose = str(metadata.get("purpose") or "")

        customer = d.get("customer") or {}
        customer_email = str(customer.get("email") or "").strip() or None

        paid_at = iso(now_utc()) if paid else None

        # Update payments
        try:
            upsert_payment_row(
                reference=reference,
                wa_phone=wa_phone or None,
                plan=plan or None,
                amount_kobo=int(amount_kobo) if amount_kobo is not None else None,
                currency=currency,
                status="success" if paid else (status or "not_success"),
                provider="paystack",
                paid_at=paid_at,
                raw_event={"verify_response": resp},
                email=customer_email,
            )
        except Exception:
            logging.exception("Failed to upsert payments row (verify)")

        # Activate subscription on successful verify (backup to webhook)
        if paid and purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
            try:
                activate_user_subscription(wa_phone, plan)
                try:
                    sb.table("user_subscriptions").update({
                        "paystack_reference": reference,
                        "last_event": "verify.success",
                        "updated_at": iso(now_utc()),
                    }).eq("wa_phone", wa_phone).execute()
                except Exception:
                    pass
            except Exception:
                logging.exception("activate_user_subscription failed (verify)")

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
# Paystack Webhook (THIS FIXES YOUR 404)
# ---------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = (request.headers.get("x-paystack-signature") or "").strip()

    if not PAYSTACK_SECRET_KEY:
        return "PAYSTACK_SECRET_KEY not set", 500

    if not verify_paystack_signature(raw, sig):
        return "invalid signature", 401

    event = request.get_json(force=True, silent=True) or {}
    event_type = str(event.get("event") or "").strip()
    data = event.get("data") or {}

    reference = str(data.get("reference") or "").strip()
    tx_id = data.get("id")

    # Idempotency key
    if tx_id:
        event_id = f"{event_type}:{tx_id}"
    elif reference:
        event_id = f"{event_type}:{reference}"
    else:
        event_id = hashlib.sha256(raw).hexdigest()

    inserted = record_paystack_event(event_id, event_type, reference or None, event)
    if not inserted:
        return "OK", 200  # Paystack retry duplicate

    status = (data.get("status") or "").lower()
    amount_kobo = data.get("amount")
    currency = data.get("currency") or CURRENCY

    metadata = data.get("metadata") or {}
    wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
    plan = str(metadata.get("plan") or "").lower()
    purpose = str(metadata.get("purpose") or "")

    customer = data.get("customer") or {}
    customer_email = str(customer.get("email") or "").strip() or None

    # Update payments row
    if reference:
        try:
            upsert_payment_row(
                reference=reference,
                wa_phone=wa_phone or None,
                plan=plan or None,
                amount_kobo=int(amount_kobo) if amount_kobo is not None else None,
                currency=currency,
                status="success" if event_type == "charge.success" else (status or event_type),
                provider="paystack",
                paid_at=iso(now_utc()) if event_type == "charge.success" else None,
                raw_event=event,
                email=customer_email,
            )
        except Exception:
            logging.exception("payments upsert failed (webhook)")

    # Activate subscription ONLY on charge.success
    if event_type == "charge.success":
        if purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
            try:
                activate_user_subscription(wa_phone, plan)
                # optional columns you showed
                try:
                    sb.table("user_subscriptions").update({
                        "paystack_reference": reference,
                        "last_event": event_type,
                        "updated_at": iso(now_utc()),
                    }).eq("wa_phone", wa_phone).execute()
                except Exception:
                    pass
            except Exception:
                logging.exception("activate_user_subscription failed (webhook)")

    return "OK", 200

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
