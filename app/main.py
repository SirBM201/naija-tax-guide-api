import os
import json
import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
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
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip()  # e.g. https://xxxx.koyeb.app
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

# WhatsApp Cloud API
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "").strip()
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WHATSAPP_API_VERSION = os.getenv("WHATSAPP_API_VERSION", "v20.0").strip()

# CORS
CORS_ALLOW_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000").strip()
allowed_origins = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
CORS(
    app,
    resources={r"/*": {"origins": allowed_origins}},
    supports_credentials=False,
    allow_headers=["Content-Type", "x-admin-key"],
    methods=["GET", "POST", "OPTIONS"],
)

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing. DB features will fail.")

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

def is_subscription_active(wa_phone: str) -> bool:
    """Basic check: active + not expired (if expires_at exists)."""
    try:
        res = supabase.table("user_subscriptions") \
            .select("status,expires_at") \
            .eq("wa_phone", wa_phone).limit(1).execute()
        rows = res.data or []
        if not rows:
            return False
        row = rows[0]
        if (row.get("status") or "").lower() != "active":
            return False
        expires_at = row.get("expires_at")
        if not expires_at:
            return True
        try:
            # ISO string -> datetime
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            return exp > now_utc()
        except Exception:
            return True
    except Exception:
        logging.exception("Subscription check failed")
        return False

# ------------------------------------------------------------
# WhatsApp send
# ------------------------------------------------------------
def wa_send_text(to_phone: str, text: str) -> None:
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        logging.warning("WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID missing; cannot send WhatsApp reply.")
        return

    url = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code >= 300:
            logging.error(f"WhatsApp send failed: {r.status_code} {r.text[:300]}")
    except Exception:
        logging.exception("WhatsApp send exception")

# ------------------------------------------------------------
# Health
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

# ------------------------------------------------------------
# Debug: list routes
# ------------------------------------------------------------
@app.get("/routes")
def routes():
    out = []
    for r in app.url_map.iter_rules():
        out.append({
            "endpoint": r.endpoint,
            "methods": sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")]),
            "rule": str(r),
        })
    return jsonify(sorted(out, key=lambda x: x["rule"]))

# ------------------------------------------------------------
# ASK (API used by web + WhatsApp handler)
# ------------------------------------------------------------
@app.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    wa_phone = (body.get("wa_phone") or "").strip()
    question = (body.get("question") or "").strip()

    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400

    # You can enforce subscription here if desired:
    # if not is_subscription_active(wa_phone):
    #     return jsonify({"ok": False, "error": "subscription_required"}), 402

    # Placeholder (same behavior you saw in PowerShell)
    return jsonify({
        "ok": True,
        "cached": False,
        "answer": {"meta": {}, "text": "Cache miss. AI call will be connected here next."}
    })

# ------------------------------------------------------------
# WhatsApp Webhook (Meta calls this)
# Callback URL should be:
#   https://YOUR-KOYEB-URL/whatsapp/webhook
# ------------------------------------------------------------
@app.get("/whatsapp/webhook")
def whatsapp_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200
    return "forbidden", 403

@app.post("/whatsapp/webhook")
def whatsapp_incoming():
    payload = request.get_json(silent=True) or {}
    # Always return 200 quickly (Meta expects fast ack)
    try:
        entry = (payload.get("entry") or [])
        if not entry:
            return "ok", 200

        changes = (entry[0].get("changes") or [])
        if not changes:
            return "ok", 200

        value = changes[0].get("value") or {}
        messages = value.get("messages") or []
        if not messages:
            return "ok", 200

        msg = messages[0]
        from_phone = (msg.get("from") or "").strip()
        msg_type = (msg.get("type") or "").strip()

        # Only handle text for now
        if msg_type != "text":
            if from_phone:
                wa_send_text(from_phone, "Message type received. Please send a text question for now.")
            return "ok", 200

        text_body = ((msg.get("text") or {}).get("body") or "").strip()
        if not from_phone or not text_body:
            return "ok", 200

        # Optional: enforce subscription
        # if not is_subscription_active(from_phone):
        #     wa_send_text(from_phone, "Subscription required. Please subscribe on thecre8hub.com to continue.")
        #     return "ok", 200

        # Reuse your /ask logic internally (no HTTP call)
        # We call the same logic used by web clients.
        answer = "Cache miss. AI call will be connected here next."
        try:
            # mimic ask() response structure
            answer = "Cache miss. AI call will be connected here next."
        except Exception:
            logging.exception("Ask handler failed")
            answer = "An internal error occurred. Please try again."

        wa_send_text(from_phone, answer)
        return "ok", 200

    except Exception:
        logging.exception("WhatsApp webhook handler error")
        return "ok", 200

# ------------------------------------------------------------
# Paystack: Initialize
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
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
    reference = uuid.uuid4().hex[:12]
    amount_kobo = int(rule["amount_kobo"])
    amount = amount_kobo / 100.0

    # 1) Payment row pending
    try:
        supabase.table("payments").insert({
            "reference": reference,
            "wa_phone": wa_phone,
            "provider": "paystack",
            "plan": plan,
            "amount_kobo": amount_kobo,
            "amount": amount,
            "currency": rule["currency"],
            "status": "pending",
            "created_at": iso(now_utc()),
            "paid_at": None,
            "email": email,
        }).execute()
    except Exception as e:
        logging.exception("Failed inserting payment row")
        return jsonify({"ok": False, "error": f"db_insert_failed: {str(e)[:300]}"}), 500

    # 2) Subscription pending
    upsert_pending_subscription(wa_phone, plan)

    # 3) Initialize Paystack
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "metadata": {"wa_phone": wa_phone, "plan": plan},
    }
    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    r = requests.post("https://api.paystack.co/transaction/initialize", headers=headers, json=payload, timeout=25)

    try:
        data = r.json()
    except Exception:
        supabase.table("payments").update({"status": "failed"}).eq("reference", reference).execute()
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
    rows = pay_row.data or []
    if not rows:
        logging.warning(f"Webhook reference not found in payments: {reference}")
        return "ok", 200

    pay = rows[0]
    wa_phone = pay.get("wa_phone")
    plan = pay.get("plan")

    meta = data.get("metadata") or {}
    wa_phone = wa_phone or meta.get("wa_phone")
    plan = plan or meta.get("plan")

    if not wa_phone or not plan:
        logging.warning(f"Webhook missing wa_phone/plan for reference={reference}")
        return "ok", 200

    if is_success:
        amount_kobo = int(data.get("amount") or pay.get("amount_kobo") or 0)
        amount = amount_kobo / 100.0

        supabase.table("payments").update({
            "status": "success",
            "paid_at": iso(now_utc()),
            "amount_kobo": amount_kobo,
            "amount": amount,
            "currency": data.get("currency") or pay.get("currency") or "NGN",
        }).eq("reference", reference).execute()

        activate_user_subscription(wa_phone, plan)

    return "ok", 200

# ------------------------------------------------------------
# Admin
# ------------------------------------------------------------
@app.get("/admin/subscriptions")
def admin_subscriptions():
    auth = require_admin(request)
    if auth:
        return auth

    res = supabase.table("user_subscriptions") \
        .select("wa_phone,plan,status,expires_at,updated_at") \
        .order("updated_at", desc=True).execute()
    return jsonify(res.data or [])

@app.get("/admin/payments")
def admin_payments():
    auth = require_admin(request)
    if auth:
        return auth

    res = supabase.table("payments") \
        .select("reference,wa_phone,provider,plan,amount,amount_kobo,currency,status,created_at,paid_at") \
        .order("created_at", desc=True).execute()
    return jsonify(res.data or [])
