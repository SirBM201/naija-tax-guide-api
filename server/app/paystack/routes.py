import os
import hmac
import hashlib
import uuid
import requests
from flask import Blueprint, request, jsonify, current_app

from app.subscriptions.service import (
    upsert_pending_payment,
    activate_or_extend_subscription,
)

paystack_bp = Blueprint("paystack_bp", __name__, url_prefix="/paystack")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")
DEFAULT_PLAN_DAYS = int(os.getenv("DEFAULT_PLAN_DAYS", "30"))

if not PAYSTACK_SECRET_KEY:
    raise RuntimeError("PAYSTACK_SECRET_KEY missing")
if not APP_BASE_URL:
    raise RuntimeError("APP_BASE_URL missing")

PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"


def _plan_amount_kobo(plan: str) -> int:
    # adjust to your pricing
    prices = {
        "BASIC": 100000,     # ₦1,000
        "STANDARD": 200000,  # ₦2,000
        "PREMIUM": 500000,   # ₦5,000
    }
    return prices.get(plan.upper().strip(), 0)


def _safe_email_from_phone(wa_phone: str) -> str:
    digits = "".join(ch for ch in (wa_phone or "") if ch.isdigit()) or "unknown"
    return f"{digits}@naijatax.local"


def _verify_signature(raw_body: bytes, signature: str) -> bool:
    if not signature:
        return False
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


@paystack_bp.post("/initialize")
def paystack_initialize():
    supabase = current_app.config["SUPABASE"]

    body = request.get_json(silent=True) or {}
    wa_phone = (body.get("wa_phone") or "").strip()
    plan = (body.get("plan") or "").strip().upper()

    if not wa_phone or not plan:
        return jsonify({"status": "error", "message": "wa_phone and plan are required"}), 400

    amount_kobo = _plan_amount_kobo(plan)
    if amount_kobo <= 0:
        return jsonify({"status": "error", "message": f"Unknown plan: {plan}"}), 400

    reference = str(uuid.uuid4())
    upsert_pending_payment(supabase, wa_phone=wa_phone, plan=plan, reference=reference)

    init_payload = {
        "email": _safe_email_from_phone(wa_phone),
        "amount": amount_kobo,
        "reference": reference,
        # Callback URL is optional for WhatsApp-only MVP (safe to keep)
        "callback_url": f"{APP_BASE_URL}/paystack/callback?ref={reference}",
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "plan_days": DEFAULT_PLAN_DAYS,
        },
    }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    r = requests.post(PAYSTACK_INIT_URL, headers=headers, json=init_payload, timeout=30)
    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text}

    if r.status_code != 200 or not data.get("status"):
        supabase.table("user_subscriptions").update({
            "last_event": "initialize_failed",
        }).eq("wa_phone", wa_phone).execute()

        return jsonify({
            "status": "error",
            "message": "Paystack initialize failed",
            "paystack_http_status": r.status_code,
            "paystack_response": data
        }), 400

    supabase.table("user_subscriptions").update({
        "last_event": "initialize_ok",
    }).eq("wa_phone", wa_phone).execute()

    return jsonify({
        "status": "ok",
        "authorization_url": data["data"]["authorization_url"],
        "reference": reference
    }), 200


@paystack_bp.post("/webhook")
def paystack_webhook():
    supabase = current_app.config["SUPABASE"]

    raw_body = request.get_data()
    signature = request.headers.get("x-paystack-signature", "")

    if not _verify_signature(raw_body, signature):
        return jsonify({"status": "error", "message": "Invalid signature"}), 401

    payload = request.get_json(silent=True) or {}
    event = payload.get("event", "")
    data = payload.get("data", {}) or {}

    reference = data.get("reference")
    metadata = data.get("metadata") or {}
    if not reference:
        return jsonify({"status": "ok"}), 200

    if event == "charge.success":
        plan = (metadata.get("plan") or "").upper() or "BASIC"
        plan_days = int(metadata.get("plan_days") or DEFAULT_PLAN_DAYS)

        activate_or_extend_subscription(
            supabase,
            reference=reference,
            plan=plan,
            plan_days=plan_days,
        )
        return jsonify({"status": "ok"}), 200

    # record other events for debugging
    supabase.table("user_subscriptions").update({
        "last_event": event or "unknown_event",
    }).eq("paystack_reference", reference).execute()

    return jsonify({"status": "ok"}), 200
