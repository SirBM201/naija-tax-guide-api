# app.py
import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, List

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)
CORS(app)

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
# Paystack signature is calculated with your secret key.
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()

APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip().rstrip("/")  # e.g. https://xxxx.koyeb.app
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "").strip().rstrip("/")  # optional

DEFAULT_PLAN_DURATION_DAYS = int(os.getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))

# Optional: if you want to protect admin-only endpoints later
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

_supabase = None

def sb():
    global _supabase
    if _supabase is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
            raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set")
        _supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _supabase

def plan_to_days(plan: str) -> int:
    p = (plan or "").lower().strip()
    if p in ("monthly", "month", "m"):
        return 30
    if p in ("quarterly", "quarter", "q"):
        return 90
    if p in ("yearly", "year", "annual", "y"):
        return 365
    # fallback
    return DEFAULT_PLAN_DURATION_DAYS

def upsert_payment_row(payload: Dict[str, Any]) -> None:
    """
    Writes/updates `public.payments` using reference as unique key.
    Expecting columns like: reference, wa_phone, provider, plan, status,
    amount_kobo, currency, email, raw_event, created_at, paid_at
    """
    sb().table("payments").upsert(payload, on_conflict="reference").execute()

def activate_user_subscription(wa_phone: str, plan: str, paystack_reference: Optional[str] = None, last_event: Optional[str] = None) -> None:
    expires_at = iso(now_utc() + timedelta(days=plan_to_days(plan)))
    sb().table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "paystack_reference": paystack_reference,
        "last_event": last_event,
        "updated_at": iso(now_utc()),
    }, on_conflict="wa_phone").execute()

def mark_subscription_inactive(wa_phone: str, plan: Optional[str] = None, last_event: Optional[str] = None) -> None:
    payload = {
        "wa_phone": wa_phone,
        "status": "inactive",
        "updated_at": iso(now_utc()),
        "last_event": last_event
    }
    if plan:
        payload["plan"] = plan
    sb().table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()

def store_paystack_event(event_id: str, event_name: str, reference: Optional[str], wa_phone: Optional[str], raw: Dict[str, Any]) -> None:
    """
    Writes into `public.paystack_events` if you created it.
    If you didn't create the table yet, this will fail—so we try/except safely.
    """
    try:
        sb().table("paystack_events").upsert({
            "event_id": event_id,
            "event": event_name,
            "reference": reference,
            "wa_phone": wa_phone,
            "raw_event": raw,
            "created_at": iso(now_utc()),
        }, on_conflict="event_id").execute()
    except Exception as e:
        logging.warning("paystack_events write skipped/failed: %s", str(e))

def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    secret = PAYSTACK_WEBHOOK_SECRET or PAYSTACK_SECRET_KEY
    if not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature or "")

# ------------------------------------------------------------
# Debug / Health
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/_routes")
def routes():
    rules: List[str] = []
    for r in app.url_map.iter_rules():
        methods = ",".join(sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")]))
        rules.append(f"{r.rule} -> {methods}")
    rules.sort()
    return jsonify({"count": len(rules), "routes": rules})

# ------------------------------------------------------------
# Paystack Initialize
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Frontend calls this to get authorization_url.
    Body: { "email": "...", "amount_kobo": 300000, "wa_phone": "...", "plan": "monthly" }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    wa_phone = (body.get("wa_phone") or "").strip()
    plan = (body.get("plan") or "").strip() or "monthly"

    amount_kobo = body.get("amount_kobo")
    if amount_kobo is None:
        # fallback to your known tiers if frontend did not send amount_kobo
        p = plan.lower()
        if p == "monthly":
            amount_kobo = 3000 * 100
        elif p == "quarterly":
            amount_kobo = 8000 * 100
        elif p == "yearly":
            amount_kobo = 30000 * 100
        else:
            amount_kobo = 3000 * 100

    if not email or not wa_phone:
        return jsonify({"ok": False, "error": "email and wa_phone are required"}), 400

    reference = f"ntg_{wa_phone}_{int(now_utc().timestamp())}"

    payload = {
        "email": email,
        "amount": int(amount_kobo),
        "reference": reference,
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
        }
    }

    r = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers={
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload),
        timeout=30
    )

    try:
        data = r.json()
    except Exception:
        data = {"status": False, "message": "Non-JSON response from Paystack", "raw": r.text}

    # store pending payment immediately
    try:
        upsert_payment_row({
            "reference": reference,
            "wa_phone": wa_phone,
            "provider": "paystack",
            "plan": plan,
            "status": "initialize",
            "amount_kobo": int(amount_kobo),
            "currency": "NGN",
            "email": email,
            "raw_event": {"initialize_request": payload, "initialize_response": data},
            "created_at": iso(now_utc()),
        })
    except Exception as e:
        logging.warning("Failed to store initialize payment row: %s", str(e))

    if not data.get("status"):
        return jsonify({"ok": False, "error": data.get("message") or "Paystack initialize failed", "data": data}), 400

    auth_url = (data.get("data") or {}).get("authorization_url")
    return jsonify({"ok": True, "reference": reference, "authorization_url": auth_url, "data": data})

# ------------------------------------------------------------
# Paystack Webhook (THIS MUST MATCH YOUR PAYSTACK URL)
# ------------------------------------------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    """
    Configure Paystack webhook URL to:
      https://<your-koyeb-domain>/webhooks/paystack
    """
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY and not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_SECRET_KEY not set", 500

    if not verify_paystack_signature(raw, sig):
        logging.warning("Paystack webhook: invalid signature")
        return "invalid signature", 401

    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception:
        logging.exception("Paystack webhook: invalid JSON")
        return "invalid json", 400

    event_name = (event.get("event") or "").strip()
    data = event.get("data") or {}

    reference = (data.get("reference") or "").strip() or None
    event_id = str(data.get("id") or reference or f"evt_{int(now_utc().timestamp())}")

    metadata = data.get("metadata") or {}
    wa_phone = (metadata.get("wa_phone") or data.get("customer", {}).get("phone") or "").strip() or None
    plan = (metadata.get("plan") or "").strip() or None
    purpose = (metadata.get("purpose") or "").strip() or None

    status = (data.get("status") or "").strip().lower()  # "success", "failed", etc.
    amount_kobo = data.get("amount")
    currency = data.get("currency")
    email = (data.get("customer") or {}).get("email") or metadata.get("email")

    # 1) Store event (idempotent)
    store_paystack_event(event_id=event_id, event_name=event_name, reference=reference, wa_phone=wa_phone, raw=event)

    # 2) Upsert payment row
    if reference:
        try:
            upsert_payment_row({
                "reference": reference,
                "wa_phone": wa_phone,
                "provider": "paystack",
                "plan": plan,
                "status": event_name or status or "webhook",
                "amount_kobo": amount_kobo,
                "currency": currency,
                "email": email,
                "raw_event": event,
                "paid_at": iso(now_utc()) if status == "success" else None,
                "created_at": iso(now_utc()),
            })
        except Exception as e:
            logging.warning("payments upsert failed: %s", str(e))

    # 3) Apply business logic (subscription/refund)
    try:
        if event_name == "charge.success" and status == "success":
            # subscription activation if metadata says so (recommended)
            if purpose == "subscription" and wa_phone and plan:
                activate_user_subscription(
                    wa_phone=wa_phone,
                    plan=plan,
                    paystack_reference=reference,
                    last_event=event_name
                )
                logging.info("Subscription activated: %s %s", wa_phone, plan)

        elif event_name in ("charge.failed", "paymentrequest.failed", "transfer.failed"):
            if wa_phone:
                mark_subscription_inactive(wa_phone=wa_phone, plan=plan, last_event=event_name)
                logging.info("Subscription marked inactive: %s", wa_phone)

        elif event_name.startswith("refund"):
            # Refund events vary; we log + mark inactive only if it’s clearly for subscription.
            if purpose == "subscription" and wa_phone:
                mark_subscription_inactive(wa_phone=wa_phone, plan=plan, last_event=event_name)
                logging.info("Refund received; subscription inactivated: %s", wa_phone)

    except Exception:
        logging.exception("Business logic error")

    return "ok", 200


# ------------------------------------------------------------
# Local dev runner (Koyeb uses gunicorn, not this)
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
