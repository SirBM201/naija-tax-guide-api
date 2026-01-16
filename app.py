# app.py
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

def env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
PAYSTACK_SECRET_KEY = env("PAYSTACK_SECRET_KEY")
# If you have a separate webhook secret, set PAYSTACK_WEBHOOK_SECRET; else it falls back to PAYSTACK_SECRET_KEY
PAYSTACK_WEBHOOK_SECRET = env("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

SUPABASE_URL = env("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = env("SUPABASE_SERVICE_ROLE_KEY")

APP_BASE_URL = env("APP_BASE_URL")  # e.g. https://xxxx.koyeb.app

DEFAULT_PLAN_DURATION_DAYS = int(env("DEFAULT_PLAN_DURATION_DAYS", "30"))


# ------------------------------------------------------------
# Supabase
# ------------------------------------------------------------
supabase = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
else:
    log.warning("Supabase env vars not fully set. Subscription writes will be skipped.")


# ------------------------------------------------------------
# Flask App
# ------------------------------------------------------------
app = Flask(__name__)
CORS(app)


# ------------------------------------------------------------
# Routes: Health + Debug Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/routes")
def routes():
    rules = []
    for r in app.url_map.iter_rules():
        methods = ",".join(sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")]))
        rules.append({"path": str(r), "methods": methods, "endpoint": r.endpoint})
    rules = sorted(rules, key=lambda x: x["path"])
    return jsonify({"count": len(rules), "routes": rules})


# ------------------------------------------------------------
# Subscription Activation
# ------------------------------------------------------------
def activate_user_subscription(wa_phone: str, plan: str) -> None:
    """
    Upserts into user_subscriptions by wa_phone.
    You must have a table: user_subscriptions(wa_phone unique, plan, status, expires_at, updated_at)
    """
    if not supabase:
        log.warning("Supabase not configured; skipping activate_user_subscription.")
        return

    expires_at = iso(now_utc() + timedelta(days=DEFAULT_PLAN_DURATION_DAYS))
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


def plan_amount_kobo(plan: str) -> int:
    """
    Your pricing:
      monthly = 3000 NGN
      quarterly = 8000 NGN
      yearly = 30000 NGN
    Paystack expects kobo.
    """
    p = (plan or "").lower().strip()
    if p == "monthly":
        return 3000 * 100
    if p == "quarterly":
        return 8000 * 100
    if p == "yearly":
        return 30000 * 100
    raise ValueError("Invalid plan. Use monthly, quarterly, or yearly.")


# ------------------------------------------------------------
# Paystack: Initialize
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    wa_phone = (body.get("wa_phone") or "").strip()
    email = (body.get("email") or "").strip()
    plan = (body.get("plan") or "").strip().lower()

    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if not email:
        return jsonify({"ok": False, "error": "email is required"}), 400

    try:
        amount = plan_amount_kobo(plan)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    callback_url = body.get("callback_url") or (APP_BASE_URL.rstrip("/") + "/paystack/callback" if APP_BASE_URL else None)

    payload = {
        "email": email,
        "amount": amount,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
        },
    }
    if callback_url:
        payload["callback_url"] = callback_url

    r = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=30,
    )

    try:
        data = r.json()
    except Exception:
        return jsonify({"ok": False, "error": "Paystack returned non-JSON response", "status_code": r.status_code}), 502

    if not r.ok or not data.get("status"):
        return jsonify({"ok": False, "error": "Paystack initialize failed", "details": data}), 400

    # data["data"] includes authorization_url, access_code, reference
    return jsonify({"ok": True, "paystack": data["data"]})


# ------------------------------------------------------------
# Paystack: Webhook (THIS is what Paystack hits)
# ------------------------------------------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    # Paystack sends POST JSON with x-paystack-signature header
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_WEBHOOK_SECRET/PAYSTACK_SECRET_KEY not set", 500

    expected = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        # Must be 401 so Paystack knows signature failed
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_name = event.get("event") or ""
    data = event.get("data") or {}
    metadata = (data.get("metadata") or {}) if isinstance(data, dict) else {}

    log.info("Paystack webhook received: event=%s", event_name)

    # Handle successful charges (subscription payment)
    if event_name == "charge.success":
        wa_phone = (metadata.get("wa_phone") or "").strip()
        plan = (metadata.get("plan") or "").strip().lower()

        if wa_phone and plan in ("monthly", "quarterly", "yearly"):
            try:
                activate_user_subscription(wa_phone=wa_phone, plan=plan)
                log.info("Subscription activated: wa_phone=%s plan=%s", wa_phone, plan)
            except Exception as e:
                log.exception("Failed activating subscription: %s", e)
                # Return 200 anyway to prevent Paystack retry storms; log is enough
        else:
            log.warning("charge.success missing metadata wa_phone/plan. metadata=%s", metadata)

    # Refund events (you said you initiated a refund)
    # Paystack can send refund.* events; we acknowledge them so Paystack stops retrying.
    if event_name.startswith("refund."):
        log.info("Refund event received: %s reference=%s", event_name, data.get("reference") or data.get("transaction_reference"))

    # Always return 200 for valid signature so Paystack stops retrying
    return "ok", 200


# ------------------------------------------------------------
# Local run (optional)
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
