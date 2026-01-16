import os
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
# Logging
# ------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("naija-tax-guide-api")

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def getenv(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = getenv("SUPABASE_SERVICE_ROLE_KEY")

PAYSTACK_SECRET_KEY = getenv("PAYSTACK_SECRET_KEY")
APP_BASE_URL = getenv("APP_BASE_URL")  # e.g. https://developed-xxxx.koyeb.app

DEFAULT_PLAN_DURATION_DAYS = int(getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))

# ------------------------------------------------------------
# Clients
# ------------------------------------------------------------
supabase = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
else:
    log.warning("Supabase env vars missing: SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY")

# ------------------------------------------------------------
# Flask App
# ------------------------------------------------------------
app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------
# Basic routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/_routes")
def list_routes():
    rules = []
    for r in app.url_map.iter_rules():
        methods = ",".join(sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")]))
        rules.append({"path": str(r), "methods": methods, "endpoint": r.endpoint})
    rules = sorted(rules, key=lambda x: x["path"])
    return jsonify({"count": len(rules), "routes": rules})

# ------------------------------------------------------------
# Subscription helper (safe even if supabase missing)
# ------------------------------------------------------------
def activate_user_subscription(wa_phone: str, plan: str) -> None:
    """
    Activates a subscription in Supabase.
    Expected table: user_subscriptions
    Columns: wa_phone (unique), plan, status, expires_at, updated_at
    """
    expires_at = iso(now_utc() + timedelta(days=DEFAULT_PLAN_DURATION_DAYS))

    if not supabase:
        log.warning("Supabase not configured; skipping activate_user_subscription")
        return

    supabase.table("user_subscriptions").upsert(
        {
            "wa_phone": wa_phone,
            "plan": plan,
            "status": "active",
            "expires_at": expires_at,
            "updated_at": iso(now_utc()),
        },
        on_conflict="wa_phone",
    ).execute()

# ------------------------------------------------------------
# Paystack: Initialize Transaction (optional)
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Body example:
    {
      "email": "customer@email.com",
      "amount": 300000,          // kobo
      "wa_phone": "2348012345678",
      "plan": "monthly"
    }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip()
    amount = payload.get("amount")
    wa_phone = (payload.get("wa_phone") or "").strip()
    plan = (payload.get("plan") or "").strip()

    if not email or not isinstance(amount, int) or amount <= 0:
        return jsonify({"ok": False, "error": "email and valid integer amount (kobo) required"}), 400

    callback_url = f"{APP_BASE_URL.rstrip('/')}/payment/success" if APP_BASE_URL else None

    data: Dict[str, Any] = {
        "email": email,
        "amount": amount,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
        },
    }
    if callback_url:
        data["callback_url"] = callback_url

    r = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers={
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        },
        data=json.dumps(data),
        timeout=30,
    )

    try:
        resp = r.json()
    except Exception:
        resp = {"ok": False, "raw": r.text}

    return jsonify(resp), r.status_code

# ------------------------------------------------------------
# Paystack Webhook (THIS is what Paystack must call)
# ------------------------------------------------------------
def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    if not PAYSTACK_SECRET_KEY:
        return False
    expected = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature or "")

def _handle_paystack_event(event: Dict[str, Any]) -> None:
    """
    Keep handler tolerant: never crash the webhook.
    """
    ev = (event.get("event") or "").strip()
    data = event.get("data") or {}
    metadata = data.get("metadata") or {}

    log.info(f"Paystack event received: {ev}")

    # Example: activate subscription on successful charge
    if ev == "charge.success":
        status = (data.get("status") or "").lower()
        if status == "success":
            wa_phone = (metadata.get("wa_phone") or "").strip()
            plan = (metadata.get("plan") or "").strip() or "monthly"
            if wa_phone:
                activate_user_subscription(wa_phone=wa_phone, plan=plan)

    # Refund events: you can log/store them if you want
    # ev could be "refund.processed", "refund.failed", etc (Paystack varies by setup)
    # We deliberately do not fail.

@app.post("/webhooks/paystack")
@app.post("/paystack/webhook")   # alias (some people use this)
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    # Always respond quickly to Paystack; do not do heavy work before returning.
    if not _verify_paystack_signature(raw, sig):
        # Important: Return 401 so you can see signature issues clearly (not 404).
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    try:
        _handle_paystack_event(event)
    except Exception as e:
        log.exception("Webhook handler error")
        # Still return 200 to prevent Paystack retry storms; log captures details.
        return "ok", 200

    return "ok", 200
