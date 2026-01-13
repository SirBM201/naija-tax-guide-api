# app/main.py
import os
import json
import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests
from flask import Flask, request, jsonify, make_response
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

# Optional
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "")  # e.g. https://developed-lizabeth-bmsconcept-e65bfd1d.koyeb.app
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "")

# CORS
# Comma-separated allowlist. Example:
# CORS_ALLOW_ORIGINS=http://localhost:3000,https://thecre8hub.com,https://www.thecre8hub.com
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "")
ALLOW_ALL_CORS = os.getenv("ALLOW_ALL_CORS", "").strip().lower() in ("1", "true", "yes")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing. Admin/Paystack will fail.")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Plans
# ------------------------------------------------------------
PLAN_RULES = {
    "monthly":   {"amount_kobo": 3000 * 100,  "days": 30,  "currency": "NGN"},
    "quarterly": {"amount_kobo": 8000 * 100,  "days": 90,  "currency": "NGN"},
    "yearly":    {"amount_kobo": 30000 * 100, "days": 365, "currency": "NGN"},
}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def _allowed_origins_list() -> list[str]:
    if not CORS_ALLOW_ORIGINS.strip():
        return []
    return [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]

def _is_origin_allowed(origin: str) -> bool:
    if ALLOW_ALL_CORS:
        return True
    allowed = _allowed_origins_list()
    if not allowed:
        return False

    # Exact match allowlist
    if origin in allowed:
        return True

    # Optional: allow any Vercel preview if you add "*.vercel.app" style entries.
    # We support a simple suffix rule: if an allowed origin starts with "*."
    # Example allowed entry: "*.vercel.app"  -> allows https://anything.vercel.app
    for a in allowed:
        if a.startswith("*.") and origin.endswith(a[1:]):  # ".vercel.app"
            return True

    return False

@app.after_request
def add_cors_headers(resp):
    """
    Adds CORS headers for browser calls (fixes 'Failed to fetch' / preflight).
    """
    origin = request.headers.get("Origin", "")
    if origin and _is_origin_allowed(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, x-admin-key, x-paystack-signature"
        # Usually not needed; keep off unless you later use cookies/credentials:
        # resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

@app.before_request
def handle_preflight():
    """
    Handles OPTIONS preflight requests globally.
    """
    if request.method == "OPTIONS":
        resp = make_response("", 204)
        return resp
    return None

def require_admin(req) -> Optional[Any]:
    key = req.headers.get("x-admin-key", "")
    if not ADMIN_API_KEY or key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    return None

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    days = PLAN_RULES.get(plan, {}).get("days", 30)
    expires_at = iso(now_utc() + timedelta(days=days))
    supabase.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

def upsert_pending_subscription(wa_phone: str, plan: str) -> None:
    supabase.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "pending",
        "expires_at": None,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

# ------------------------------------------------------------
# Health
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

# ------------------------------------------------------------
# Paystack: Initialize
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Body JSON:
    {
      "email": "user@email.com",
      "wa_phone": "2348....",
      "plan": "monthly|quarterly|yearly"
    }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    wa_phone = (body.get("wa_phone") or "").strip()
    plan = (body.get("plan") or "").strip().lower()

    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "Valid email is required"}), 400
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if plan not in PLAN_RULES:
        return jsonify({"ok": False, "error": f"Invalid plan. Use {list(PLAN_RULES.keys())}"}), 400

    rule = PLAN_RULES[plan]
    reference = uuid.uuid4().hex[:10]

    # 1) Create payment row as pending
    supabase.table("payments").insert({
        "reference": reference,
        "wa_phone": wa_phone,
        "provider": "paystack",
        "plan": plan,
        "amount_kobo": rule["amount_kobo"],
        "currency": rule["currency"],
        "status": "pending",
        "created_at": iso(now_utc()),
        "paid_at": None,
        "email": email,
    }).execute()

    # 2) Pending subscription
    upsert_pending_subscription(wa_phone, plan)

    # 3) Initialize Paystack
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "email": email,
        "amount": rule["amount_kobo"],
        "reference": reference,
        "metadata": {"wa_phone": wa_phone, "plan": plan},
    }

    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    r = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers=headers,
        json=payload,
        timeout=25,
    )

    try:
        data = r.json()
    except Exception:
        return jsonify({"ok": False, "error": f"Paystack non-JSON response: {r.text[:200]}"}), 502

    if r.status_code >= 300 or not data.get("status"):
        supabase.table("payments").update({"status": "failed"}).eq("reference", reference).execute()
        msg = data.get("message") or f"HTTP {r.status_code}"
        return jsonify({"ok": False, "error": f"Paystack init failed: {msg}"}), 400

    auth_url = (data.get("data") or {}).get("authorization_url")
    return jsonify({"ok": True, "reference": reference, "authorization_url": auth_url})

# ------------------------------------------------------------
# Paystack: Webhook
# ------------------------------------------------------------
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_WEBHOOK_SECRET not set", 500

    expected = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception:
        return "invalid json", 400

    event_type = event.get("event", "")
    data = event.get("data") or {}
    reference = data.get("reference") or ""

    is_success = event_type in ("charge.success", "transaction.success")

    if not reference:
        return "ok", 200

    pay_row = supabase.table("payments").select("*").eq("reference", reference).limit(1).execute()
    pay = (pay_row.data or [])
    if not pay:
        logging.warning(f"Webhook reference not found in payments: {reference}")
        return "ok", 200

    pay = pay[0]
    wa_phone = pay.get("wa_phone")
    plan = pay.get("plan")

    meta = data.get("metadata") or {}
    wa_phone = wa_phone or meta.get("wa_phone")
    plan = plan or meta.get("plan")

    if not wa_phone or not plan:
        logging.warning(f"Webhook missing wa_phone/plan for reference={reference}")
        return "ok", 200

    if is_success:
        supabase.table("payments").update({
            "status": "success",
            "paid_at": iso(now_utc()),
            "amount_kobo": data.get("amount") or pay.get("amount_kobo"),
            "currency": data.get("currency") or pay.get("currency") or "NGN",
        }).eq("reference", reference).execute()

        activate_user_subscription(wa_phone, plan)
        return "ok", 200

    return "ok", 200

# ------------------------------------------------------------
# Admin: Subscriptions + Payments (return ARRAYS)
# ------------------------------------------------------------
@app.get("/admin/subscriptions")
def admin_subscriptions():
    auth = require_admin(request)
    if auth:
        return auth

    res = (
        supabase.table("user_subscriptions")
        .select("wa_phone,plan,status,expires_at,updated_at")
        .order("updated_at", desc=True)
        .execute()
    )
    return jsonify(res.data or [])

@app.get("/admin/payments")
def admin_payments():
    auth = require_admin(request)
    if auth:
        return auth

    res = (
        supabase.table("payments")
        .select("reference,wa_phone,provider,plan,amount_kobo,currency,status,created_at,paid_at")
        .order("created_at", desc=True)
        .execute()
    )
    return jsonify(res.data or [])
