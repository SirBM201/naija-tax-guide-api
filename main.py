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

APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/").strip()

# Admin key for protected admin/cron endpoints
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

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
    return re.sub(r"\D", "", (wa_phone or "").strip())

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack: HMAC-SHA512 of raw request body using PAYSTACK_SECRET_KEY.
    Header: x-paystack-signature
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

def require_admin(req) -> bool:
    if not ADMIN_API_KEY:
        return False
    key = (req.headers.get("x-admin-key") or "").strip()
    return key == ADMIN_API_KEY

# ------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------
def record_paystack_event(event_id: str, event_type: str, reference: Optional[str], payload: Dict[str, Any]) -> bool:
    """
    Returns True if inserted; False if duplicate.
    Requires public.paystack_events.event_id UNIQUE (you already created it).
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

def activate_user_subscription(wa_phone: str, plan: str, reference: Optional[str] = None, last_event: Optional[str] = None) -> None:
    plan = (plan or "").lower()
    wa_phone = normalize_wa_phone(wa_phone)

    expires_at = iso(now_utc() + timedelta(days=days_for_plan(plan)))

    # Keep this aligned with your table columns (you showed paystack_reference and last_event exist)
    payload = {
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc()),
    }
    if reference:
        payload["paystack_reference"] = reference
    if last_event:
        payload["last_event"] = last_event

    sb.table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()

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
    Matches your payments columns shown: reference, wa_phone, provider, plan,
    amount_kobo, currency, status, created_at, paid_at, raw_event, email
    """
    row: Dict[str, Any] = {
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

    # pre-create payment row as "initialized"
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
# Paystack Verify (called by frontend payment-success page)
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

        paid_at = iso(now_utc()) if paid else None

        # record payment row
        try:
            upsert_payment_row(
                reference=reference,
                wa_phone=wa_phone or None,
                plan=plan or None,
                amount_kobo=int(amount_kobo) if amount_kobo is not None else None,
                currency=currency,
                status="success" if paid else status or "not_success",
                provider="paystack",
                paid_at=paid_at,
                raw_event={"verify_response": resp},
                email=str(d.get("customer", {}).get("email") or "") or None,
            )
        except Exception:
            logging.exception("Failed to upsert payments row (verify)")

        # If successful, activate subscription
        if paid and wa_phone and plan in PLAN_PRICES:
            activate_user_subscription(wa_phone, plan, reference=reference, last_event="verify.success")

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
# Paystack Webhook (Paystack calls THIS)
# ---------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    raw_body = request.get_data() or b""
    signature = request.headers.get("x-paystack-signature", "")

    # IMPORTANT: Always log webhook hits (even if invalid) to see traffic in Koyeb logs.
    logging.info("Paystack webhook HIT: len=%s signature_present=%s", len(raw_body), bool(signature))

    if not PAYSTACK_SECRET_KEY:
        logging.error("PAYSTACK_SECRET_KEY not set")
        return "PAYSTACK_SECRET_KEY not set", 500

    if not verify_paystack_signature(raw_body, signature):
        logging.warning("Paystack webhook invalid signature")
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_type = str(event.get("event") or "")
    data = event.get("data", {}) or {}

    reference = str(data.get("reference") or "")
    status = str(data.get("status") or "").lower()
    amount_kobo = data.get("amount")
    currency = str(data.get("currency") or CURRENCY)

    metadata = data.get("metadata", {}) or {}
    wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
    plan = str(metadata.get("plan") or "").lower()
    purpose = str(metadata.get("purpose") or "")

    # idempotency key: Paystack data.id is best
    event_id = str(data.get("id") or reference or uuid.uuid4().hex)

    inserted = record_paystack_event(event_id, event_type, reference or None, event)
    logging.info("Paystack event received: type=%s ref=%s inserted=%s status=%s wa=%s plan=%s",
                 event_type, reference, inserted, status, wa_phone, plan)

    # Update payments row for every event (so you always see what happened)
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
            raw_event=event,
            email=str(data.get("customer", {}).get("email") or "") or None,
        )
    except Exception:
        logging.exception("Failed to upsert payments row (webhook)")

    # Activate subscription only when successful charge
    if event_type == "charge.success":
        if purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
            try:
                activate_user_subscription(wa_phone, plan, reference=reference, last_event="charge.success")
            except Exception:
                logging.exception("activate_user_subscription failed")

    return "ok", 200

# ------------------------------------------------------------
# Main (local)
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
