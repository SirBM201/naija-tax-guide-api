import os
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, request, jsonify

from supabase import create_client

app = Flask(__name__)

# -----------------------------
# ENV
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)  # same in most setups

APP_PUBLIC_BASE_URL = os.getenv("APP_PUBLIC_BASE_URL", "").rstrip("/")  # e.g. https://your-koyeb-app.koyeb.app
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "info@thecre8hub.com")
SUPPORT_PHONE = os.getenv("SUPPORT_PHONE", "+2347034941158")

# Pricing in kobo (NGN)
PLAN_PRICES_KOBO = {
    "monthly": 3000 * 100,
    "quarterly": 8000 * 100,
    "yearly": 30000 * 100,
}

# Duration logic
PLAN_DAYS = {
    "monthly": 30,
    "quarterly": 90,
    "yearly": 365,
}

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# -----------------------------
# Helpers
# -----------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def parse_wa_phone(raw: str) -> str:
    # Expecting like "234703..." already. Keep simple.
    return raw.strip().replace("+", "").replace(" ", "")

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    if not signature:
        return False
    mac = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(mac, signature)

def send_whatsapp_message(to_phone: str, text: str) -> None:
    """
    Sends a WhatsApp message via Cloud API.
    """
    if not (WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID):
        return

    url = f"https://graph.facebook.com/v20.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text}
    }
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    try:
        requests.post(url, headers=headers, json=payload, timeout=15)
    except Exception:
        pass

def upsert_user(wa_phone: str) -> Dict[str, Any]:
    """
    Ensures a user row exists. Updates last_seen_at.
    """
    wa_phone = parse_wa_phone(wa_phone)

    # fetch
    res = supabase.table("users").select("*").eq("wa_phone", wa_phone).limit(1).execute()
    if res.data:
        user = res.data[0]
        supabase.table("users").update({"last_seen_at": now_utc().isoformat()}).eq("id", user["id"]).execute()
        return user

    # create
    insert = {
        "wa_phone": wa_phone,
        "state": "idle",
        "last_seen_at": now_utc().isoformat(),
    }
    created = supabase.table("users").insert(insert).execute()
    return created.data[0]

def get_active_subscription(user_id: str) -> Optional[Dict[str, Any]]:
    res = (
        supabase.table("subscriptions")
        .select("*")
        .eq("user_id", user_id)
        .eq("status", "active")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None

def expire_if_needed(user_id: str) -> None:
    """
    On each inbound message, enforce expiry.
    """
    sub = get_active_subscription(user_id)
    if not sub:
        return
    end_at = sub.get("end_at")
    if not end_at:
        return
    # supabase returns ISO string
    end_dt = datetime.fromisoformat(end_at.replace("Z", "+00:00"))
    if now_utc() >= end_dt:
        supabase.table("subscriptions").update({"status": "expired"}).eq("id", sub["id"]).execute()

def is_subscribed(user_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    expire_if_needed(user_id)
    sub = get_active_subscription(user_id)
    return (sub is not None, sub)

def make_pay_link_payload(wa_phone: str, plan: str, email: str) -> Dict[str, Any]:
    if plan not in PLAN_PRICES_KOBO:
        raise ValueError("Invalid plan")
    amount = PLAN_PRICES_KOBO[plan]
    return {
        "email": email,
        "amount": amount,
        "currency": "NGN",
        "reference": f"NTG_{wa_phone}_{int(now_utc().timestamp())}",
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "product": "Naija Tax Guide",
        },
        # optional: redirect back to your website
        "callback_url": f"{APP_PUBLIC_BASE_URL}/payment-success" if APP_PUBLIC_BASE_URL else None,
    }

def safe_json() -> Dict[str, Any]:
    try:
        return request.get_json(force=True, silent=True) or {}
    except Exception:
        return {}


# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "naija-tax-guide-api"})


# =========================================================
# WhatsApp webhook (verification + inbound)
# =========================================================
@app.get("/webhook")
def whatsapp_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200
    return "Forbidden", 403


@app.post("/webhook")
def whatsapp_inbound():
    payload = safe_json()

    # WhatsApp Cloud payload structure (minimal extraction)
    try:
        entry = payload.get("entry", [])[0]
        changes = entry.get("changes", [])[0]
        value = changes.get("value", {})
        messages = value.get("messages", [])
        if not messages:
            return jsonify({"ok": True})

        msg = messages[0]
        from_phone = msg.get("from", "")
        text = (msg.get("text", {}) or {}).get("body", "").strip()

        if not from_phone:
            return jsonify({"ok": True})

        user = upsert_user(from_phone)
        user_id = user["id"]

        subscribed, sub = is_subscribed(user_id)

        if not subscribed:
            # subscription required
            reply = (
                "Welcome to Naija Tax Guide.\n\n"
                "To continue, subscribe:\n"
                "1) Monthly – ₦3,000\n"
                "2) Quarterly – ₦8,000\n"
                "3) Yearly – ₦30,000\n\n"
                "Reply with: monthly / quarterly / yearly"
            )
            # if user already typed a plan, generate pay link
            plan = text.lower()
            if plan in PLAN_PRICES_KOBO:
                # Use a fallback email (Paystack requires email)
                email = f"{parse_wa_phone(from_phone)}@naijatax.local"
                init = create_paystack_transaction(parse_wa_phone(from_phone), plan, email)
                reply = (
                    f"Great. Click to pay for {plan} plan:\n{init['authorization_url']}\n\n"
                    "After payment, your subscription activates automatically."
                )

            send_whatsapp_message(parse_wa_phone(from_phone), reply)
            return jsonify({"ok": True})

        # subscribed user: handle commands or stub response
        if text.lower() in ("help", "menu"):
            send_whatsapp_message(parse_wa_phone(from_phone),
                "You are active.\nSend your tax question now, or type MENU anytime."
            )
            return jsonify({"ok": True})

        # Placeholder for your Tax logic / cached Q&A / AI
        send_whatsapp_message(parse_wa_phone(from_phone),
            "Received. Your request is being processed.\n\n(Next step: connect your Tax Q&A engine here.)"
        )
        return jsonify({"ok": True})

    except Exception:
        # Always return 200 to WhatsApp to avoid retries storms; log in Koyeb console.
        return jsonify({"ok": True})


# =========================================================
# Paystack Initialize
# =========================================================
def create_paystack_transaction(wa_phone: str, plan: str, email: str) -> Dict[str, Any]:
    wa_phone = parse_wa_phone(wa_phone)
    plan = plan.lower().strip()

    if plan not in PLAN_PRICES_KOBO:
        raise ValueError("Invalid plan")

    # Ensure user exists
    user = upsert_user(wa_phone)

    payload = make_pay_link_payload(wa_phone, plan, email)
    # remove None fields (callback_url optional)
    payload = {k: v for k, v in payload.items() if v is not None}

    r = requests.post("https://api.paystack.co/transaction/initialize",
                      headers=paystack_headers(),
                      data=json.dumps(payload),
                      timeout=20)
    data = r.json()
    if not data.get("status"):
        raise RuntimeError(data.get("message", "Paystack initialize failed"))

    ref = data["data"]["reference"]

    # create pending subscription record
    supabase.table("subscriptions").insert({
        "user_id": user["id"],
        "plan": plan,
        "status": "pending",
        "paystack_ref": ref,
        "amount_kobo": PLAN_PRICES_KOBO[plan],
        "currency": "NGN",
    }).execute()

    return {
        "authorization_url": data["data"]["authorization_url"],
        "access_code": data["data"]["access_code"],
        "reference": ref,
    }


@app.post("/paystack/initialize")
def paystack_initialize():
    body = safe_json()
    wa_phone = parse_wa_phone(str(body.get("wa_phone", "")).strip())
    plan = str(body.get("plan", "")).strip().lower()
    email = str(body.get("email", "")).strip().lower()

    if not wa_phone or not plan or not email:
        return jsonify({"ok": False, "error": "wa_phone, plan, email required"}), 400

    try:
        result = create_paystack_transaction(wa_phone, plan, email)
        return jsonify({"ok": True, **result})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# =========================================================
# Paystack Webhook (activate subscription)
# =========================================================
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data()  # bytes
    signature = request.headers.get("x-paystack-signature", "")

    if not verify_paystack_signature(raw, signature):
        return "Invalid signature", 401

    event = request.get_json(force=True, silent=True) or {}
    event_type = event.get("event", "")
    data = event.get("data", {}) or {}

    # We only care about successful charge events
    if event_type not in ("charge.success",):
        return jsonify({"ok": True})

    reference = data.get("re

