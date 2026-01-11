# app/main.py
import os
import re
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests
from flask import Flask, request, jsonify
from supabase import create_client
from flask_cors import CORS

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")  # e.g. https://thecre8hub.com

# Use FRONTEND_ORIGINS on Koyeb (comma-separated)
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "").strip()
DEFAULT_PLAN_DURATION_DAYS = int(os.getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))

PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify/"
PROVIDER = "paystack"

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------
cors_origins = []
if FRONTEND_ORIGINS:
    cors_origins = [o.strip() for o in FRONTEND_ORIGINS.split(",") if o.strip()]

# allow requests from your frontend domain(s)
CORS(
    app,
    resources={r"/*": {"origins": cors_origins or "*"}},
    supports_credentials=False,
)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def safe_text(v: Any) -> str:
    return str(v or "").strip()

def normalize_wa_phone(wa_phone: str) -> str:
    s = safe_text(wa_phone)
    s = re.sub(r"[^\d+]", "", s)  # keep + and digits
    return s

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def safe_email(email: str, wa_phone: str) -> str:
    e = safe_text(email).lower()
    if e and "@" in e:
        return e
    digits = re.sub(r"\D", "", wa_phone or "") or "user"
    return f"user_{digits}@thecre8hub.local"

def fetch_plan(plan: str) -> Optional[Dict[str, Any]]:
    """
    Reads from public.plans:
      plan (text) PRIMARY KEY
      amount_kobo (int8)
      duration_days (int4)
      currency (text)
    """
    plan = safe_text(plan).lower()
    res = supabase.table("plans").select("amount_kobo,duration_days,currency").eq("plan", plan).limit(1).execute()
    rows = res.data or []
    return rows[0] if rows else None

def upsert_subscription_pending(
    wa_phone: str,
    email: str,
    plan: str,
    reference: str,
    amount_kobo: int,
    currency: str,
    duration_days: int,
) -> None:
    """
    Writes into public.user_subscriptions.
    Your table should have at least:
      wa_phone (text unique)
      plan (text)
      status (text)
      paystack_reference (text)
      last_event (text)
      amount_kobo (int8)  <-- ensure exists, then reload schema cache
      currency (text)
      duration_days (int4)
      email (text)
      expires_at (timestamptz nullable)
      updated_at (timestamptz)
    """
    row = {
        "wa_phone": wa_phone,
        "email": email,
        "plan": plan,
        "status": "pending",
        "paystack_reference": reference,
        "last_event": "charge.initialize",
        "amount_kobo": int(amount_kobo),
        "currency": currency,
        "duration_days": int(duration_days),
        "expires_at": None,
        "updated_at": iso(now_utc()),
    }
    supabase.table("user_subscriptions").upsert(row, on_conflict="wa_phone").execute()

def activate_user_subscription(wa_phone: str, plan: str, duration_days: int) -> None:
    expires_at = now_utc() + timedelta(days=int(duration_days or DEFAULT_PLAN_DURATION_DAYS))
    supabase.table("user_subscriptions").upsert(
        {
            "wa_phone": wa_phone,
            "plan": plan,
            "status": "active",
            "expires_at": iso(expires_at),
            "last_event": "charge.success",
            "updated_at": iso(now_utc()),
        },
        on_conflict="wa_phone",
    ).execute()

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True}), 200

@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Called by frontend:
      { wa_phone, email, plan }

    Returns:
      { ok: true, authorization_url, reference }
    """
    try:
        payload_in = request.get_json(silent=True) or {}
        wa_phone = normalize_wa_phone(payload_in.get("wa_phone"))
        email = safe_email(payload_in.get("email"), wa_phone)
        plan = safe_text(payload_in.get("plan")).lower()

        if not PAYSTACK_SECRET_KEY:
            return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500
        if not APP_BASE_URL:
            return jsonify({"ok": False, "error": "APP_BASE_URL not set"}), 500
        if not wa_phone or not plan:
            return jsonify({"ok": False, "error": "wa_phone and plan are required"}), 400

        plan_row = fetch_plan(plan)
        if not plan_row:
            return jsonify({"ok": False, "error": f"Invalid plan '{plan}'"}), 400

        amount_kobo = int(plan_row["amount_kobo"])
        duration_days = int(plan_row.get("duration_days") or DEFAULT_PLAN_DURATION_DAYS)
        currency = safe_text(plan_row.get("currency") or "NGN")

        # Use a short readable reference (Paystack requires unique)
        # Example: ntg_234xxxxxxxxxx_1700000000
        ref = f"ntg_{re.sub(r'[^0-9]', '', wa_phone)[:20]}_{int(now_utc().timestamp())}"

        # Save pending subscription in Supabase (so verify/webhook can activate)
        try:
            upsert_subscription_pending(
                wa_phone=wa_phone,
                email=email,
                plan=plan,
                reference=ref,
                amount_kobo=amount_kobo,
                currency=currency,
                duration_days=duration_days,
            )
        except Exception as e:
            logging.exception("Failed to upsert pending subscription")
            # Continue anyway; Paystack can still initialize, but you should fix schema cache
            # so DB writes succeed consistently.

        init_payload = {
            "email": email,
            "amount": amount_kobo,
            "currency": currency,
            "reference": ref,
            # IMPORTANT: redirect back to FRONTEND success page
            "callback_url": f"{APP_BASE_URL}/payment-success",
            "metadata": {
                "wa_phone": wa_phone,
                "plan": plan,
                "provider": PROVIDER,
            },
        }

        r = requests.post(PAYSTACK_INIT_URL, headers=paystack_headers(), json=init_payload, timeout=30)
        data = r.json() if r.content else {}

        if r.status_code >= 400 or not data.get("status"):
            return jsonify({"ok": False, "error": "paystack_init_failed", "detail": data}), 502

        return jsonify(
            {
                "ok": True,
                "authorization_url": data["data"]["authorization_url"],
                "reference": data["data"].get("reference") or ref,
            }
        ), 200

    except Exception as e:
        logging.exception("initialize error")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/paystack/verify")
def paystack_verify():
    """
    Frontend calls this from /payment-success page:
      { reference }

    We verify with Paystack, then activate subscription in Supabase.
    """
    try:
        body = request.get_json(silent=True) or {}
        reference = safe_text(body.get("reference"))

        if not PAYSTACK_SECRET_KEY:
            return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500
        if not reference:
            return jsonify({"ok": False, "error": "reference required"}), 400

        vr = requests.get(PAYSTACK_VERIFY_URL + reference, headers=paystack_headers(), timeout=30)
        vdata = vr.json() if vr.content else {}

        if vr.status_code >= 400 or not vdata.get("status"):
            return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": vdata}), 502

        pdata = vdata.get("data") or {}
        status = safe_text(pdata.get("status"))

        # Pull metadata we stored during initialize
        meta = pdata.get("metadata") or {}
        wa_phone = normalize_wa_phone(meta.get("wa_phone") or "")
        plan = safe_text(meta.get("plan") or "").lower()

        if status != "success":
            return jsonify({"ok": False, "error": f"payment_not_success ({status})", "reference": reference}), 200

        if not wa_phone or not plan:
            # fallback: try to resolve by paystack_reference in user_subscriptions
            res = supabase.table("user_subscriptions").select("wa_phone,plan,duration_days").eq("paystack_reference", reference).limit(1).execute()
            rows = res.data or []
            if rows:
                wa_phone = normalize_wa_phone(rows[0]["wa_phone"])
                plan = safe_text(rows[0]["plan"]).lower()
                duration_days = int(rows[0].get("duration_days") or DEFAULT_PLAN_DURATION_DAYS)
            else:
                return jsonify({"ok": False, "error": "missing_metadata_and_no_db_match"}), 200
        else:
            # fetch duration from plans table
            plan_row = fetch_plan(plan) or {}
            duration_days = int(plan_row.get("duration_days") or DEFAULT_PLAN_DURATION_DAYS)

        activate_user_subscription(wa_phone=wa_phone, plan=plan, duration_days=duration_days)

        # Update last_event + updated_at
        supabase.table("user_subscriptions").update(
            {"last_event": "verify.success", "updated_at": iso(now_utc())}
        ).eq("wa_phone", wa_phone).execute()

        return jsonify({"ok": True, "reference": reference, "wa_phone": wa_phone, "plan": plan}), 200

    except Exception as e:
        logging.exception("verify error")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.post("/paystack/webhook")
def paystack_webhook():
    """
    Paystack webhook to auto-activate without waiting for the success page.
    """
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY:
        return "PAYSTACK_SECRET_KEY not set", 500

    expected = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_name = safe_text(event.get("event"))
    data = event.get("data") or {}

    try:
        reference = safe_text(data.get("reference"))
        meta = data.get("metadata") or {}
        wa_phone = normalize_wa_phone(meta.get("wa_phone") or "")
        plan = safe_text(meta.get("plan") or "").lower()

        logging.info(f"Webhook event={event_name} reference={reference} wa={wa_phone} plan={plan}")

        if event_name in ("charge.success", "subscription.create", "invoice.payment_succeeded"):
            # resolve duration
            plan_row = fetch_plan(plan) or {}
            duration_days = int(plan_row.get("duration_days") or DEFAULT_PLAN_DURATION_DAYS)

            if not wa_phone:
                # fallback by paystack_reference in DB
                res = supabase.table("user_subscriptions").select("wa_phone,plan,duration_days").eq("paystack_reference", reference).limit(1).execute()
                rows = res.data or []
                if rows:
                    wa_phone = normalize_wa_phone(rows[0]["wa_phone"])
                    plan = safe_text(rows[0]["plan"]).lower()
                    duration_days = int(rows[0].get("duration_days") or duration_days)

            if wa_phone and plan:
                activate_user_subscription(wa_phone=wa_phone, plan=plan, duration_days=duration_days)
                supabase.table("user_subscriptions").update(
                    {"last_event": event_name, "updated_at": iso(now_utc())}
                ).eq("wa_phone", wa_phone).execute()

        else:
            # store last_event for debugging if wa_phone exists
            if wa_phone:
                supabase.table("user_subscriptions").update(
                    {"last_event": event_name, "updated_at": iso(now_utc())}
                ).eq("wa_phone", wa_phone).execute()

        return "ok", 200

    except Exception:
        logging.exception("webhook handler error")
        # Paystack expects 200 to stop retries; return 200 but log errors
        return "ok", 200
