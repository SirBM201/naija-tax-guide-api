# app/main.py
import os
import json
import hmac
import hashlib
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Dict, Tuple

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
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "")  # e.g. https://xxxx.koyeb.app
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "")

# WhatsApp Cloud API
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "").strip()
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()

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
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing. Admin/Paystack/WhatsApp logic may fail.")

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

def get_subscription_status(wa_phone: str) -> Dict[str, Any]:
    res = supabase.table("user_subscriptions").select("*").eq("wa_phone", wa_phone).limit(1).execute()
    rows = res.data or []
    return rows[0] if rows else {}

def normalize_text(s: str) -> str:
    return (s or "").strip()

# ---------------------------
# WhatsApp send message
# ---------------------------
def wa_send_text(to_phone: str, text: str) -> Tuple[bool, str]:
    """
    Sends a WhatsApp text message to a user via Cloud API.
    to_phone should be in international format without '+' ideally (Meta accepts both in many cases).
    """
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        return False, "WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID not set"

    url = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
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
        r = requests.post(url, headers=headers, json=payload, timeout=25)
        if r.status_code >= 300:
            return False, f"HTTP {r.status_code}: {r.text[:300]}"
        return True, "sent"
    except Exception as e:
        return False, str(e)[:300]

# ---------------------------
# Build replies for commands
# ---------------------------
def reply_help() -> str:
    return (
        "Naija Tax Guide Commands:\n"
        "1) HELP - show commands\n"
        "2) PLANS - view subscription plans\n"
        "3) SUBSCRIBE - how to subscribe\n"
        "4) STATUS - check your subscription status\n\n"
        "Or just ask your tax question directly."
    )

def reply_plans() -> str:
    return (
        "Subscription Plans:\n"
        "- MONTHLY: ₦3,000\n"
        "- QUARTERLY: ₦8,000\n"
        "- YEARLY: ₦30,000\n\n"
        "Send SUBSCRIBE to get the payment link instructions."
    )

def reply_subscribe() -> str:
    base = (PUBLIC_BASE_URL or "").rstrip("/")
    if base:
        return (
            "To subscribe:\n"
            "1) Go to the website and choose a plan.\n"
            f"2) Website: {base}\n"
            "3) After payment, your WhatsApp access activates automatically.\n\n"
            "You can also reply with: MONTHLY, QUARTERLY, or YEARLY."
        )
    return (
        "To subscribe:\n"
        "1) Choose a plan: MONTHLY / QUARTERLY / YEARLY\n"
        "2) You will receive payment instructions.\n"
        "3) After payment, your WhatsApp access activates automatically."
    )

def reply_status(wa_phone: str) -> str:
    sub = get_subscription_status(wa_phone)
    if not sub:
        return "No subscription record found for your number yet. Send PLANS or SUBSCRIBE to get started."

    status = sub.get("status") or "unknown"
    plan = sub.get("plan") or "-"
    expires_at = sub.get("expires_at") or "-"
    return f"Your subscription:\n- Plan: {plan}\n- Status: {status}\n- Expires: {expires_at}"

# ------------------------------------------------------------
# Health + Routes
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.get("/routes")
def routes():
    output = []
    for r in app.url_map.iter_rules():
        output.append({
            "endpoint": r.endpoint,
            "methods": sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")]),
            "rule": str(r)
        })
    return jsonify(sorted(output, key=lambda x: x["rule"]))

# ------------------------------------------------------------
# Core Ask (placeholder today, AI later)
# ------------------------------------------------------------
@app.post("/ask")
def ask():
    """
    Current behavior: cache/DB lookup then AI (later).
    For now, returns a placeholder that shows cache miss.
    """
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_text(body.get("wa_phone"))
    question = normalize_text(body.get("question"))

    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400

    # TODO: implement cache lookup + AI call
    return jsonify({
        "ok": True,
        "cached": False,
        "answer": {"meta": "", "text": "Cache miss. AI call will be connected here next."}
    })

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

    upsert_pending_subscription(wa_phone, plan)

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "metadata": {"wa_phone": wa_phone, "plan": plan}
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
# WhatsApp Webhook (Meta verification + inbound messages)
# ------------------------------------------------------------
@app.get("/whatsapp/webhook")
def whatsapp_webhook_verify():
    """
    Meta verification request includes:
    hub.mode, hub.verify_token, hub.challenge
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token and WHATSAPP_VERIFY_TOKEN and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200

    # This is why you see "forbidden" in browser — it’s normal without the correct args/token.
    return "forbidden", 403

@app.post("/whatsapp/webhook")
def whatsapp_webhook_inbound():
    """
    Receives inbound WhatsApp events. We:
    - extract text messages
    - handle commands
    - otherwise pass into /ask
    - reply via Cloud API
    """
    payload = request.get_json(silent=True) or {}
    try:
        entries = payload.get("entry") or []
        for entry in entries:
            changes = entry.get("changes") or []
            for change in changes:
                value = change.get("value") or {}
                messages = value.get("messages") or []
                for msg in messages:
                    from_phone = str(msg.get("from") or "").strip()
                    msg_type = msg.get("type")

                    if not from_phone:
                        continue

                    text = ""
                    if msg_type == "text":
                        text = ((msg.get("text") or {}).get("body") or "").strip()

                    if not text:
                        # ignore non-text for now
                        continue

                    upper = text.strip().upper()

                    # Commands
                    if upper in ("HELP", "MENU"):
                        wa_send_text(from_phone, reply_help())
                        continue

                    if upper in ("PLANS", "PLAN"):
                        wa_send_text(from_phone, reply_plans())
                        continue

                    if upper in ("SUBSCRIBE", "BUY"):
                        wa_send_text(from_phone, reply_subscribe())
                        continue

                    if upper in ("STATUS", "CHECK"):
                        wa_send_text(from_phone, reply_status(from_phone))
                        continue

                    # Quick plan keywords
                    if upper in ("MONTHLY", "QUARTERLY", "YEARLY"):
                        wa_send_text(from_phone, f"You selected {upper}. Please subscribe via the website or request a payment link from the web flow.\n\nSend SUBSCRIBE for instructions.")
                        continue

                    # Default: route into /ask logic (internal call)
                    with app.test_request_context(
                        "/ask",
                        method="POST",
                        json={"wa_phone": from_phone, "question": text},
                    ):
                        resp = ask()
                        # resp is Flask response; convert to dict
                        if isinstance(resp, tuple):
                            resp_obj, status = resp
                            data = resp_obj.get_json(silent=True) or {}
                        else:
                            data = resp.get_json(silent=True) or {}

                    answer = data.get("answer") or {}
                    reply_text = answer.get("text") or "OK"

                    wa_send_text(from_phone, reply_text)

        return "ok", 200
    except Exception:
        logging.exception("WhatsApp webhook processing failed")
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
