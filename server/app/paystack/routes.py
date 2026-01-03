import os
import json
import hmac
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import requests
from flask import Blueprint, request, jsonify

paystack_bp = Blueprint("paystack_bp", __name__, url_prefix="/paystack")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

if not PAYSTACK_SECRET_KEY:
    raise RuntimeError("PAYSTACK_SECRET_KEY missing")

if not APP_BASE_URL:
    raise RuntimeError("APP_BASE_URL missing (e.g. https://your-koyeb-app.koyeb.app)")

PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"


# -----------------------------
# Helpers
# -----------------------------
def _utcnow():
    return datetime.now(timezone.utc)


def _plan_amount_kobo(plan: str) -> int:
    """
    Change these to your real pricing.
    Amount is in KOBO (₦1000 = 100000 kobo).
    """
    plan = (plan or "").strip().upper()
    prices = {
        "BASIC": 100000,     # ₦1,000
        "STANDARD": 200000,  # ₦2,000
        "PREMIUM": 500000,   # ₦5,000
    }
    return prices.get(plan, 0)


def _plan_days(plan: str) -> int:
    """
    For now, all are 30-day plans.
    You can change logic later (weekly/annual).
    """
    return 30


def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack sends: x-paystack-signature
    This should equal HMAC-SHA512(raw_body, secret_key)
    """
    if not signature:
        return False
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


def _safe_email_from_phone(wa_phone: str) -> str:
    """
    Paystack requires an email.
    If user has no email, generate a safe placeholder.
    """
    digits = "".join(ch for ch in (wa_phone or "") if ch.isdigit())
    if not digits:
        digits = "unknown"
    return f"{digits}@naijatax.local"


# -----------------------------
# Routes
# -----------------------------
@paystack_bp.post("/initialize")
def paystack_initialize():
    """
    Expected JSON:
    {
      "wa_phone": "2348012345678",
      "plan": "BASIC"
    }

    Returns:
    {
      "status": "ok",
      "authorization_url": "https://checkout.paystack.com/....",
      "reference": "...."
    }
    """
    supabase = request.app.config["SUPABASE"] if hasattr(request, "app") else None
    # Flask doesn't attach app to request by default; use current_app instead:
    from flask import current_app
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

    # 1) Upsert subscription as pending
    #    (If user already exists, overwrite with pending for this new payment)
    now = _utcnow().isoformat()
    upsert_payload = {
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "pending",
        "paystack_reference": reference,
        "last_event": "initialize_created",
        "updated_at": now,
    }

    # Try to preserve created_at if DB default exists; if not, you can set it
    # upsert_payload["created_at"] = now

    supabase.table("user_subscriptions").upsert(upsert_payload).execute()

    # 2) Call Paystack initialize
    email = _safe_email_from_phone(wa_phone)
    callback_url = f"{APP_BASE_URL}/paystack/callback?ref={reference}"

    init_payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "callback_url": callback_url,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "plan_days": _plan_days(plan),
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
            "updated_at": _utcnow().isoformat(),
        }).eq("wa_phone", wa_phone).execute()

        return jsonify({
            "status": "error",
            "message": "Paystack initialize failed",
            "paystack_http_status": r.status_code,
            "paystack_response": data
        }), 400

    auth_url = data["data"]["authorization_url"]

    # update last_event
    supabase.table("user_subscriptions").update({
        "last_event": "initialize_ok",
        "updated_at": _utcnow().isoformat(),
    }).eq("wa_phone", wa_phone).execute()

    return jsonify({
        "status": "ok",
        "authorization_url": auth_url,
        "reference": reference
    }), 200


@paystack_bp.post("/webhook")
def paystack_webhook():
    """
    Paystack Webhook endpoint.
    - Verifies x-paystack-signature
    - On charge.success: activates subscription
    """
    from flask import current_app
    supabase = current_app.config["SUPABASE"]

    raw_body = request.get_data()  # bytes
    signature = request.headers.get("x-paystack-signature", "")

    if not _verify_paystack_signature(raw_body, signature):
        return jsonify({"status": "error", "message": "Invalid signature"}), 401

    payload = request.get_json(silent=True) or {}
    event = payload.get("event", "")
    data = payload.get("data", {}) or {}

    reference = data.get("reference")
    metadata = (data.get("metadata") or {}) if isinstance(data.get("metadata"), dict) else {}

    wa_phone = metadata.get("wa_phone")
    plan = (metadata.get("plan") or "").upper()
    plan_days = int(metadata.get("plan_days") or _plan_days(plan))

    # If metadata is missing, we can still try to find by reference
    if not reference:
        return jsonify({"status": "ok"}), 200  # ignore malformed

    # Only act on success payment events
    if event == "charge.success":
        # Compute new expiry
        expires_at = (_utcnow() + timedelta(days=plan_days)).isoformat()

        # Activate
        # If you want to ensure phone matches, prefer reference-based update:
        update_payload = {
            "status": "active",
            "expires_at": expires_at,
            "last_event": "charge.success",
            "paystack_reference": reference,
            "updated_at": _utcnow().isoformat(),
        }

        # If plan exists in metadata, update it too
        if plan:
            update_payload["plan"] = plan

        # Update by reference (most reliable)
        supabase.table("user_subscriptions").update(update_payload).eq("paystack_reference", reference).execute()

        return jsonify({"status": "ok"}), 200

    # For other events: record and ignore
    supabase.table("user_subscriptions").update({
        "last_event": event or "unknown_event",
        "updated_at": _utcnow().isoformat(),
    }).eq("paystack_reference", reference).execute()

    return jsonify({"status": "ok"}), 200
