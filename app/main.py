# app/main.py
import os
import re
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, request, jsonify
from supabase import create_client

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

# Your public website base URL (Paystack callback goes here)
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

# CORS - you said you are using FRONTEND_ORIGINS (comma-separated)
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "").strip()

# Optional settings
DEFAULT_PLAN_DURATION_DAYS = int(os.getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))
SERVICE_NAME = os.getenv("SERVICE_NAME", "Naija Tax Guide")

PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify/"

# ------------------------------------------------------------
# Clients
# ------------------------------------------------------------
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing. Supabase calls will fail.")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY) if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY else None


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def safe_text(v: Any) -> str:
    return (str(v) if v is not None else "").strip()

def normalize_wa_phone(wa_phone: str) -> str:
    s = safe_text(wa_phone)
    s = re.sub(r"[^\d+]", "", s)
    return s

def cors_origin_allowed(origin: str) -> bool:
    if not origin:
        return False
    allowed = [o.strip() for o in (FRONTEND_ORIGINS or "").split(",") if o.strip()]
    return origin in allowed

@app.after_request
def add_cors_headers(resp):
    origin = request.headers.get("Origin", "")
    if cors_origin_allowed(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return resp

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True}), 200

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def get_plan_from_supabase(plan: str) -> Tuple[int, int, str]:
    """
    Reads plan pricing from Supabase `plans` table.
    Expected columns: plan (text), amount_kobo (int), duration_days (int), currency (text)
    """
    if not supabase:
        raise RuntimeError("Supabase client not configured")

    plan = safe_text(plan).lower()
    res = (
        supabase.table("plans")
        .select("amount_kobo,duration_days,currency")
        .eq("plan", plan)
        .limit(1)
        .execute()
    )
    row = (res.data or [])
    if not row:
        raise ValueError(f"Unknown plan: {plan}")

    amount_kobo = int(row[0].get("amount_kobo") or 0)
    duration_days = int(row[0].get("duration_days") or DEFAULT_PLAN_DURATION_DAYS)
    currency = safe_text(row[0].get("currency") or "NGN")

    if amount_kobo <= 0:
        raise ValueError(f"Invalid plan amount_kobo for plan={plan}")

    return amount_kobo, duration_days, currency

def upsert_pending_subscription(wa_phone: str, email: str, plan: str, amount_kobo: int, duration_days: int, currency: str, paystack_reference: str):
    if not supabase:
        raise RuntimeError("Supabase client not configured")

    # IMPORTANT: only include columns you truly have in user_subscriptions
    payload = {
        "wa_phone": wa_phone,
        "email": email,
        "plan": plan,
        "status": "pending",
        "amount_kobo": amount_kobo,
        "currency": currency,
        "duration_days": duration_days,
        "paystack_reference": paystack_reference,
        "last_event": "charge.initialize",
        "updated_at": iso(now_utc()),
    }

    supabase.table("user_subscriptions").upsert(
        payload,
        on_conflict="wa_phone"
    ).execute()

def activate_user_subscription(wa_phone: str, plan: str, duration_days: int):
    if not supabase:
        raise RuntimeError("Supabase client not configured")

    expires_at = iso(now_utc() + timedelta(days=int(duration_days)))

    supabase.table("user_subscriptions").upsert(
        {
            "wa_phone": wa_phone,
            "plan": plan,
            "status": "active",
            "expires_at": expires_at,
            "updated_at": iso(now_utc()),
            "last_event": "charge.success",
        },
        on_conflict="wa_phone"
    ).execute()

def mark_failed(wa_phone: str, reason: str):
    if not supabase:
        raise RuntimeError("Supabase client not configured")

    supabase.table("user_subscriptions").upsert(
        {
            "wa_phone": wa_phone,
            "status": "failed",
            "last_event": reason,
            "updated_at": iso(now_utc()),
        },
        on_conflict="wa_phone"
    ).execute()


# ------------------------------------------------------------
# Paystack: Initialize
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Creates a Paystack transaction and redirects Paystack to:
    {APP_BASE_URL}/payment-success?reference=...
    """
    data = request.get_json(silent=True) or {}
    wa_phone = normalize_wa_phone(data.get("wa_phone"))
    email = safe_text(data.get("email")).lower()
    plan = safe_text(data.get("plan")).lower()

    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500
    if not APP_BASE_URL:
        return jsonify({"ok": False, "error": "APP_BASE_URL not set"}), 500
    if not wa_phone or not email or not plan:
        return jsonify({"ok": False, "error": "wa_phone, email, plan required"}), 400

    try:
        amount_kobo, duration_days, currency = get_plan_from_supabase(plan)

        # Use Paystack reference generated by Paystack OR a custom one.
        # Paystack allows custom, but we can let Paystack generate to reduce issues.
        # However, webhook + verify returns `reference` always.
        # We'll generate our own short reference:
        reference = f"ntg_{re.sub(r'\\D','',wa_phone)}_{int(now_utc().timestamp())}"

        # Save pending in Supabase BEFORE calling Paystack
        upsert_pending_subscription(
            wa_phone=wa_phone,
            email=email,
            plan=plan,
            amount_kobo=amount_kobo,
            duration_days=duration_days,
            currency=currency,
            paystack_reference=reference,
        )

        payload = {
            "email": email,
            "amount": int(amount_kobo),
            "currency": currency,
            "reference": reference,
            "callback_url": f"{APP_BASE_URL}/payment-success",
            "metadata": {
                "wa_phone": wa_phone,
                "plan": plan,
                "service": SERVICE_NAME,
            },
        }

        r = requests.post(PAYSTACK_INIT_URL, headers=paystack_headers(), json=payload, timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            logging.error("Paystack init failed: %s", resp)
            mark_failed(wa_phone, "charge.initialize_failed")
            return jsonify({"ok": False, "error": "paystack_init_failed", "detail": resp}), 502

        auth_url = resp["data"]["authorization_url"]
        paystack_ref = resp["data"].get("reference") or reference

        # Keep the final reference
        supabase.table("user_subscriptions").upsert(
            {
                "wa_phone": wa_phone,
                "paystack_reference": paystack_ref,
                "last_event": "charge.initialize",
                "updated_at": iso(now_utc()),
            },
            on_conflict="wa_phone"
        ).execute()

        return jsonify({
            "ok": True,
            "authorization_url": auth_url,
            "reference": paystack_ref
        }), 200

    except Exception as e:
        logging.exception("Initialize error")
        return jsonify({"ok": False, "error": str(e)}), 500


# ------------------------------------------------------------
# Paystack: Verify (called by frontend success page)
# ------------------------------------------------------------
@app.post("/paystack/verify")
def paystack_verify():
    """
    Frontend calls this after Paystack redirects to /payment-success.
    """
    data = request.get_json(silent=True) or {}
    reference = safe_text(data.get("reference") or data.get("trxref"))

    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500
    if not reference:
        return jsonify({"ok": False, "error": "reference required"}), 400

    try:
        url = f"{PAYSTACK_VERIFY_URL}{reference}"
        r = requests.get(url, headers=paystack_headers(), timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": resp}), 502

        data2 = resp.get("data") or {}
        status = safe_text(data2.get("status"))  # "success", "failed", "abandoned"
        metadata = data2.get("metadata") or {}
        wa_phone = normalize_wa_phone(metadata.get("wa_phone"))
        plan = safe_text(metadata.get("plan")).lower()

        # If metadata missing, try to find wa_phone from DB by reference
        if (not wa_phone) and supabase:
            q = (
                supabase.table("user_subscriptions")
                .select("wa_phone,plan,duration_days")
                .eq("paystack_reference", reference)
                .limit(1)
                .execute()
            )
            row = (q.data or [])
            if row:
                wa_phone = safe_text(row[0].get("wa_phone"))
                if not plan:
                    plan = safe_text(row[0].get("plan")).lower()

        if not wa_phone:
            return jsonify({"ok": False, "error": "Could not resolve wa_phone for this reference"}), 400

        # Update last_event always for traceability
        if supabase:
            supabase.table("user_subscriptions").upsert(
                {
                    "wa_phone": wa_phone,
                    "paystack_reference": reference,
                    "last_event": f"verify.{status}",
                    "updated_at": iso(now_utc()),
                },
                on_conflict="wa_phone"
            ).execute()

        if status == "success":
            # compute duration_days from plans
            amount_kobo, duration_days, currency = get_plan_from_supabase(plan)
            activate_user_subscription(wa_phone=wa_phone, plan=plan, duration_days=duration_days)

            return jsonify({
                "ok": True,
                "status": "success",
                "wa_phone": wa_phone,
                "plan": plan
            }), 200

        # not successful
        return jsonify({"ok": False, "error": f"Payment not successful: {status}", "status": status}), 200

    except Exception as e:
        logging.exception("Verify error")
        return jsonify({"ok": False, "error": str(e)}), 500


# ------------------------------------------------------------
# Paystack: Webhook (server-to-server)
# ------------------------------------------------------------
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY:
        return "PAYSTACK_SECRET_KEY not set", 500

    expected = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_type = safe_text(event.get("event"))
    data = event.get("data") or {}
    metadata = data.get("metadata") or {}

    reference = safe_text(data.get("reference"))
    wa_phone = normalize_wa_phone(metadata.get("wa_phone"))
    plan = safe_text(metadata.get("plan")).lower()

    logging.info("Webhook received: %s ref=%s wa=%s plan=%s", event_type, reference, wa_phone, plan)

    try:
        # Trace event
        if supabase and wa_phone:
            supabase.table("user_subscriptions").upsert(
                {
                    "wa_phone": wa_phone,
                    "paystack_reference": reference or None,
                    "last_event": event_type or "webhook",
                    "updated_at": iso(now_utc()),
                },
                on_conflict="wa_phone"
            ).execute()

        # Activate on success event
        if event_type in ("charge.success", "subscription.create", "invoice.payment_succeeded"):
            if wa_phone and plan:
                _, duration_days, _ = get_plan_from_supabase(plan)
                activate_user_subscription(wa_phone=wa_phone, plan=plan, duration_days=duration_days)
                return "ok", 200

        return "ok", 200

    except Exception:
        logging.exception("Webhook handling error")
        return "error", 500
