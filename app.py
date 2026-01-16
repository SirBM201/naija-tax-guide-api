# app.py
import os
import re
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
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

CURRENCY = "NGN"

PLAN_PRICES = {
    "monthly": 300000,
    "quarterly": 800000,
    "yearly": 3000000,
}

# ------------------------------------------------------------
# Supabase
# ------------------------------------------------------------
sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------
CORS(app, resources={r"/*": {"origins": "*"}})

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def normalize_wa_phone(v: str) -> str:
    return re.sub(r"\D", "", (v or "").strip())

def days_for_plan(plan: str) -> int:
    return {"monthly": 30, "quarterly": 90, "yearly": 365}.get(plan, 30)

def verify_paystack_signature(raw: bytes, signature: str) -> bool:
    if not PAYSTACK_SECRET_KEY or not signature:
        return False
    expected = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# ------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------
def record_paystack_event(event_id: str, event_type: str, reference: Optional[str], payload: Dict[str, Any]) -> bool:
    try:
        sb.table("paystack_events").insert({
            "event_id": event_id,
            "event_type": event_type,
            "reference": reference,
            "payload": payload,
        }).execute()
        return True
    except Exception:
        # duplicate (idempotency)
        return False

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

    sb.table("payments").upsert(row, on_conflict="reference").execute()

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    wa_phone = normalize_wa_phone(wa_phone)
    expires_at = iso(now_utc() + timedelta(days=days_for_plan(plan)))

    sb.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc()),
    }, on_conflict="wa_phone").execute()

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

# ------------------------------------------------------------
# PAYSTACK WEBHOOK  ✅ THIS FIXES YOUR 404
# ------------------------------------------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "").strip()

    if not verify_paystack_signature(raw, sig):
        return "invalid signature", 401

    event = request.get_json(force=True, silent=True) or {}
    event_type = str(event.get("event") or "")
    data = event.get("data") or {}

    reference = str(data.get("reference") or "")
    tx_id = data.get("id")

    if tx_id:
        event_id = f"{event_type}:{tx_id}"
    elif reference:
        event_id = f"{event_type}:{reference}"
    else:
        event_id = hashlib.sha256(raw).hexdigest()

    # Idempotency
    if not record_paystack_event(event_id, event_type, reference, event):
        return "OK", 200

    status = (data.get("status") or "").lower()
    amount_kobo = data.get("amount")
    currency = data.get("currency") or CURRENCY

    metadata = data.get("metadata") or {}
    wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
    plan = str(metadata.get("plan") or "").lower()
    purpose = str(metadata.get("purpose") or "")

    if reference:
        upsert_payment_row(
            reference=reference,
            wa_phone=wa_phone or None,
            plan=plan or None,
            amount_kobo=int(amount_kobo) if amount_kobo else None,
            currency=currency,
            status="success" if event_type == "charge.success" else status,
            paid_at=iso(now_utc()) if event_type == "charge.success" else None,
            raw_event=event,
        )

    if event_type == "charge.success":
        if purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
            activate_user_subscription(wa_phone, plan)

    return "OK", 200

# ------------------------------------------------------------
# Local run
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
