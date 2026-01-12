import os
import re
import hmac
import hashlib
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# -------------------------------------------------
# ENV
# -------------------------------------------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").strip()

DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://thecre8hub.com",
    "https://www.thecre8hub.com",
]

PLAN_DAYS = {
    "monthly": 30,
    "quarterly": 90,
    "yearly": 365,
}

PLAN_AMOUNTS_NGN = {
    "monthly": 3000,
    "quarterly": 8000,
    "yearly": 30000,
}

def parse_origins(value: str):
    if not value:
        return DEFAULT_ORIGINS
    return [v.strip() for v in value.split(",") if v.strip()]

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def normalize_wa_phone(s: str) -> str:
    # store digits only, no "+"
    return re.sub(r"\D", "", (s or "").strip())

# -------------------------------------------------
# APP
# -------------------------------------------------
app = Flask(__name__)

CORS(
    app,
    resources={r"/*": {"origins": parse_origins(CORS_ORIGINS)}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Paystack-Signature"],
    max_age=86400,
)

sb = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def activate_user_subscription(wa_phone: str, plan: str) -> None:
    """
    Upsert into user_subscriptions.
    Requires unique constraint on wa_phone.
    """
    if not sb:
        raise RuntimeError("Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)")

    plan = (plan or "").lower().strip()
    days = PLAN_DAYS.get(plan, 30)

    expires_at = iso(now_utc() + timedelta(days=days))

    sb.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

def already_processed_reference(reference: str) -> bool:
    """
    Uses paystack_events table to avoid processing duplicates.
    Table must exist:
      reference TEXT UNIQUE
    """
    if not sb:
        return False
    ref = (reference or "").strip()
    if not ref:
        return False

    res = sb.table("paystack_events").select("reference").eq("reference", ref).limit(1).execute()
    data = getattr(res, "data", None) or []
    return len(data) > 0

def mark_processed(reference: str, event: str, raw: dict) -> None:
    if not sb:
        return
    sb.table("paystack_events").insert({
        "reference": reference,
        "event": event,
        "raw": raw
    }).execute()

def paystack_signature_ok(raw_body: bytes, signature: str) -> bool:
    if not PAYSTACK_SECRET_KEY or not signature:
        return False
    expected = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(expected, signature)

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Body:
    {
      "email": "user@email.com",
      "wa_phone": "234xxxxxxxxxx",
      "plan": "monthly|quarterly|yearly",
      "callback_url": "https://yourdomain.com/payment-success"
    }
    amount is derived from plan (so users cannot cheat)
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip()
    wa_phone = normalize_wa_phone(str(data.get("wa_phone", "")))
    plan = str(data.get("plan", "")).strip().lower()
    callback_url = str(data.get("callback_url", "")).strip()

    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "valid_email_required"}), 400
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone_required"}), 400
    if plan not in ("monthly", "quarterly", "yearly"):
        return jsonify({"ok": False, "error": "invalid_plan"}), 400
    if not callback_url:
        return jsonify({"ok": False, "error": "callback_url_required"}), 400

    amount_ngn = PLAN_AMOUNTS_NGN[plan]
    amount_kobo = int(amount_ngn * 100)

    payload = {
        "email": email,
        "amount": amount_kobo,
        "currency": "NGN",
        "callback_url": callback_url,
        # metadata ensures webhook/verify can activate subscription
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
        },
    }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers=headers,
            timeout=30,
        )
        result = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    if resp.status_code != 200 or result.get("status") is not True:
        return jsonify({"ok": False, "error": "paystack_initialize_failed", "detail": result}), 400

    d = result.get("data", {}) or {}
    return jsonify({
        "ok": True,
        "authorization_url": d.get("authorization_url"),
        "access_code": d.get("access_code"),
        "reference": d.get("reference"),
        "amount": amount_ngn,
        "plan": plan,
        "wa_phone": wa_phone,
    }), 200

@app.post("/paystack/verify")
def paystack_verify():
    """
    Body: { "reference": "xxxx" }

    NOTE: Webhook is the main source of truth.
    Verify is kept for the frontend payment-success page UX.
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}
    reference = str(data.get("reference", "")).strip()
    if not reference:
        return jsonify({"ok": False, "error": "reference_required"}), 400

    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        payload = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    if resp.status_code != 200:
        return jsonify({"ok": False, "error": "paystack_http_error", "detail": payload}), 502

    if payload.get("status") is not True:
        return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": payload}), 400

    d = payload.get("data") or {}
    paystack_status = str(d.get("status", "")).lower()
    paid = (paystack_status == "success")

    amount_kobo = d.get("amount")
    amount = amount_kobo / 100 if isinstance(amount_kobo, (int, float)) else None

    md = d.get("metadata") or {}
    wa_phone = normalize_wa_phone(str(md.get("wa_phone", "")))
    plan = str(md.get("plan", "")).strip().lower()

    return jsonify({
        "ok": True,
        "paid": paid,
        "reference": reference,
        "status": paystack_status,
        "amount": amount,
        "currency": d.get("currency"),
        "wa_phone": wa_phone,
        "plan": plan,
        "note": "Webhook activates subscription. Verify is for user feedback only."
    }), 200

@app.post("/paystack/webhook")
def paystack_webhook():
    """
    Paystack Webhook:
    - verifies x-paystack-signature
    - processes only charge.success
    - activates subscription using metadata.wa_phone + metadata.plan
    - prevents duplicate processing using paystack_events.reference UNIQUE
    """
    raw = request.get_data() or b""
    signature = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY:
        return "PAYSTACK_SECRET_KEY not set", 500

    if not paystack_signature_ok(raw, signature):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_type = str(event.get("event", "")).strip().lower()
    data = event.get("data") or {}

    # We only activate on successful charge
    if event_type != "charge.success":
        return "ignored", 200

    reference = str(data.get("reference", "")).strip()
    if not reference:
        return "missing reference", 400

    # Duplicate protection
    if already_processed_reference(reference):
        return "duplicate ignored", 200

    # Validate metadata
    md = data.get("metadata") or {}
    wa_phone = normalize_wa_phone(str(md.get("wa_phone", "")))
    plan = str(md.get("plan", "")).strip().lower()

    if plan not in ("monthly", "quarterly", "yearly"):
        # still mark processed to avoid infinite retries if metadata is wrong
        mark_processed(reference, event_type, event)
        return "invalid plan in metadata", 400

    if not wa_phone:
        mark_processed(reference, event_type, event)
        return "missing wa_phone in metadata", 400

    try:
        # Activate subscription
        activate_user_subscription(wa_phone, plan)

        # Mark processed
        mark_processed(reference, event_type, event)

        return "ok", 200
    except Exception as e:
        # do NOT mark processed so Paystack can retry later if Supabase was down
        return f"error: {str(e)}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
