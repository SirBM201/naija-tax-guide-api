import os
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

import requests
from flask import Flask, request, jsonify, make_response
from supabase import create_client

# ------------------------------------------------------------
# Flask
# ------------------------------------------------------------
app = Flask(__name__)

# ------------------------------------------------------------
# Env
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")

APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")  # e.g. https://xxxx.koyeb.app
DEFAULT_PLAN_DAYS = int(os.getenv("DEFAULT_PLAN_DAYS", "30"))

SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "120"))  # not used heavily here

# ------------------------------------------------------------
# Basic validation
# ------------------------------------------------------------
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    # Don't crash hard in production; allow /health to respond so you can diagnose
    print("WARN: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing.")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

WHATSAPP_API_BASE = "https://graph.facebook.com/v20.0"  # stable
WHATSAPP_MESSAGES_URL = f"{WHATSAPP_API_BASE}/{WHATSAPP_PHONE_NUMBER_ID}/messages"

PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"


# ------------------------------------------------------------
# Helpers: WhatsApp
# ------------------------------------------------------------
def send_whatsapp_text(to_phone: str, text: str) -> Tuple[bool, str]:
    """
    Send a WhatsApp text message via Cloud API.
    Returns (ok, info).
    """
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        return False, "Missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID"

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
        r = requests.post(WHATSAPP_MESSAGES_URL, headers=headers, json=payload, timeout=30)
        ok = r.status_code in (200, 201)
        return ok, r.text
    except Exception as e:
        return False, f"send_whatsapp_text exception: {e}"


def extract_inbound_message(payload: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Extract (wa_phone, text, message_id) from WhatsApp webhook payload.
    Returns None if not a normal inbound text.
    """
    try:
        entry = payload.get("entry", [])[0]
        changes = entry.get("changes", [])[0]
        value = changes.get("value", {})
        messages = value.get("messages", [])
        if not messages:
            return None

        msg = messages[0]
        wa_phone = msg.get("from")
        message_id = msg.get("id")
        msg_type = msg.get("type")

        text = ""
        if msg_type == "text":
            text = msg.get("text", {}).get("body", "").strip()
        elif msg_type == "button":
            text = msg.get("button", {}).get("text", "").strip()
        elif msg_type == "interactive":
            interactive = msg.get("interactive", {})
            # handle list_reply/button_reply
            if "list_reply" in interactive:
                text = interactive["list_reply"].get("title", "").strip()
            elif "button_reply" in interactive:
                text = interactive["button_reply"].get("title", "").strip()

        if not wa_phone or not message_id:
            return None

        return {"wa_phone": wa_phone, "text": text or "", "message_id": message_id}
    except Exception:
        return None


# ------------------------------------------------------------
# Helpers: Supabase
# ------------------------------------------------------------
def log_webhook_event(payload: Dict[str, Any]) -> None:
    # optional debug table
    try:
        supabase.table("webhook_events").insert({"payload": payload}).execute()
    except Exception:
        pass


def dedup_inbound(message_id: str) -> bool:
    """
    Returns True if message_id is new and saved.
    Returns False if it already exists (duplicate).
    """
    try:
        # Insert; if conflict, supabase will error. We'll pre-check instead for simplicity.
        existing = supabase.table("webhook_dedup").select("message_id").eq("message_id", message_id).execute()
        if existing.data:
            return False
        supabase.table("webhook_dedup").insert({"message_id": message_id}).execute()
        return True
    except Exception:
        # If anything odd happens, be safe and avoid double reply
        return False


def ensure_user(wa_phone: str) -> None:
    try:
        supabase.table("users").upsert({"wa_phone": wa_phone}).execute()
    except Exception:
        pass


def get_plan_row(plan: str) -> Optional[Dict[str, Any]]:
    try:
        r = supabase.table("plans").select("*").eq("plan", plan).eq("is_active", True).limit(1).execute()
        return r.data[0] if r.data else None
    except Exception:
        return None


def get_subscription(wa_phone: str) -> Optional[Dict[str, Any]]:
    try:
        r = supabase.table("user_subscriptions").select("*").eq("wa_phone", wa_phone).limit(1).execute()
        return r.data[0] if r.data else None
    except Exception:
        return None


def set_subscription_active(wa_phone: str, plan: str, duration_days: int, reference: str, event: str) -> Dict[str, Any]:
    """
    Activate or replace subscription.
    """
    expires_at = (datetime.now(timezone.utc) + timedelta(days=duration_days)).isoformat()

    payload = {
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "paystack_reference": reference,
        "last_event": event,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    # upsert by wa_phone primary key
    supabase.table("user_subscriptions").upsert(payload).execute()
    return payload


def set_payment_status(reference: str, status: str, meta: Dict[str, Any]) -> None:
    try:
        supabase.table("payments").upsert({
            "reference": reference,
            "status": status,
            "meta": meta,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, on_conflict="reference").execute()
    except Exception:
        pass


# ------------------------------------------------------------
# Helpers: Business (Commands)
# ------------------------------------------------------------
def normalize_plan_name(s: str) -> str:
    s = (s or "").strip().lower()
    if s in ("basic", "standard", "premium"):
        return s
    return ""


def format_menu(sub: Optional[Dict[str, Any]]) -> str:
    status_line = "Plan: FREE"
    if sub and sub.get("plan"):
        plan = sub.get("plan", "free").upper()
        expires_at = sub.get("expires_at")
        if expires_at:
            status_line = f"Plan: {plan}\nExpires: {expires_at}"
        else:
            status_line = f"Plan: {plan}"

    return (
        "Naija Tax Guide 🇳🇬\n\n"
        f"{status_line}\n\n"
        "Commands:\n"
        "1) MENU\n"
        "2) UPGRADE BASIC\n"
        "3) UPGRADE STANDARD\n"
        "4) UPGRADE PREMIUM\n"
        "5) HELP\n"
    )


def handle_inbound_text(wa_phone: str, text: str) -> str:
    t = (text or "").strip()
    t_upper = t.upper()

    sub = get_subscription(wa_phone)

    if t_upper in ("MENU", "START", "HI", "HELLO"):
        return format_menu(sub)

    if t_upper == "HELP":
        return (
            "Help:\n"
            "- Type MENU to see options\n"
            "- Type UPGRADE BASIC / STANDARD / PREMIUM to get payment link\n"
            "- After payment, your plan activates automatically.\n"
        )

    if t_upper.startswith("UPGRADE"):
        parts = t_upper.split()
        if len(parts) < 2:
            return "Please use: UPGRADE BASIC or UPGRADE STANDARD or UPGRADE PREMIUM"
        plan = normalize_plan_name(parts[1].lower())
        if not plan:
            return "Unknown plan. Use: BASIC, STANDARD, or PREMIUM."
        # We do NOT initialize Paystack here; we return instruction and your frontend/bot flow will call /paystack/initialize.
        return f"To upgrade to {plan.upper()}, I am preparing your payment link… (please wait 2–5 seconds and send UPGRADE {plan.upper()} again if you don’t receive a link)."

    # Default fallback
    return "I didn’t understand. Type MENU to see options."


# ------------------------------------------------------------
# Routes: Health
# ------------------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "naija-tax-guide-api"})


# ------------------------------------------------------------
# Routes: WhatsApp Webhook
#   - GET for verification
#   - POST for inbound messages
# ------------------------------------------------------------
@app.get("/whatsapp/webhook")
def whatsapp_verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return make_response(challenge, 200)

    return make_response("Verification failed", 403)


@app.post("/whatsapp/webhook")
def whatsapp_inbound():
    payload = request.get_json(silent=True) or {}
    log_webhook_event(payload)

    inbound = extract_inbound_message(payload)
    if not inbound:
        # Meta also sends status updates; respond 200 so it stops retrying
        return jsonify({"ok": True})

    wa_phone = inbound["wa_phone"]
    text = inbound["text"]
    message_id = inbound["message_id"]

    # Dedup
    if not dedup_inbound(message_id):
        return jsonify({"ok": True, "dedup": True})

    ensure_user(wa_phone)

    # Handle message
    reply = handle_inbound_text(wa_phone, text)

    ok, info = send_whatsapp_text(wa_phone, reply)

    # Optional outbound log
    try:
        supabase.table("outbound_messages").insert({
            "message_id": message_id,
            "to_phone": wa_phone,
            "inbound_text": text,
            "reply_text": reply,
            "sent_ok": ok,
            "send_info": info,
        }).execute()
    except Exception:
        pass

    return jsonify({"ok": True})


# Alias so you can use /webhook in Meta settings if you want
@app.get("/webhook")
def webhook_alias_verify():
    return whatsapp_verify()


@app.post("/webhook")
def webhook_alias_inbound():
    return whatsapp_inbound()


# ------------------------------------------------------------
# Routes: Paystack Initialize
#   Called by your bot/server when user wants a payment link.
#   You can call it from WhatsApp flow or from your admin/test tool.
# ------------------------------------------------------------
@app.post("/paystack/initialize")
def paystack_initialize():
    data = request.get_json(silent=True) or {}

    wa_phone = (data.get("wa_phone") or "").strip()
    plan = normalize_plan_name(data.get("plan") or "")

    if not wa_phone or not plan:
        return jsonify({"ok": False, "error": "wa_phone and plan are required"}), 400

    plan_row = get_plan_row(plan)
    if not plan_row:
        return jsonify({"ok": False, "error": f"Plan not found or inactive: {plan}"}), 400

    amount_kobo = int(plan_row["amount_kobo"])
    duration_days = int(plan_row["duration_days"])

    # Paystack requires an email. If you don't have user's email, use a placeholder.
    # You can later collect email in WhatsApp onboarding.
    customer_email = data.get("email") or f"{wa_phone}@naijatax.local"

    # Paystack callback URL is optional for WhatsApp-only flow.
    # Webhook is what activates subscription.
    callback_url = f"{APP_BASE_URL}/paystack/callback" if APP_BASE_URL else None

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    init_payload = {
        "email": customer_email,
        "amount": amount_kobo,
        "currency": plan_row.get("currency", "NGN"),
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "duration_days": duration_days,
        },
    }
    if callback_url:
        init_payload["callback_url"] = callback_url

    try:
        r = requests.post(PAYSTACK_INIT_URL, headers=headers, json=init_payload, timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code not in (200, 201) or not resp.get("status"):
            return jsonify({"ok": False, "error": "Paystack init failed", "details": resp}), 400

        reference = resp["data"]["reference"]
        auth_url = resp["data"]["authorization_url"]

        # Record payment initiated
        set_payment_status(reference, "initiated", {"plan": plan, "wa_phone": wa_phone})

        return jsonify({
            "ok": True,
            "plan": plan,
            "amount_kobo": amount_kobo,
            "duration_days": duration_days,
            "reference": reference,
            "authorization_url": auth_url,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": f"Paystack init exception: {e}"}), 500


# Optional callback endpoint (only needed if you use redirect flows; WhatsApp-only can ignore)
@app.get("/paystack/callback")
def paystack_callback():
    # Paystack redirects here after payment if callback_url was set.
    # We still rely on webhook for activation.
    ref = request.args.get("reference") or request.args.get("trxref") or ""
    return jsonify({"ok": True, "message": "Callback received. Subscription activates via webhook.", "reference": ref})


# ------------------------------------------------------------
# Routes: Paystack Webhook
#   Set Paystack Dashboard webhook to: https://<koyeb>/paystack/webhook
# ------------------------------------------------------------
@app.post("/paystack/webhook")
def paystack_webhook():
    # Verify signature
    signature = request.headers.get("x-paystack-signature", "")
    body = request.get_data()  # raw bytes

    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY missing"}), 500

    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        body,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed, signature):
        return jsonify({"ok": False, "error": "Invalid signature"}), 401

    event = request.get_json(silent=True) or {}
    event_type = event.get("event", "")
    data = event.get("data", {}) or {}

    reference = data.get("reference", "")
    status = data.get("status", "")
    metadata = data.get("metadata", {}) or {}

    wa_phone = (metadata.get("wa_phone") or "").strip()
    plan = normalize_plan_name(metadata.get("plan") or "")

    # Store payment status
    set_payment_status(reference, status or "unknown", {"event": event_type, "raw": data})

    # Only activate on success
    if event_type == "charge.success" and status == "success" and wa_phone and plan:
        plan_row = get_plan_row(plan)
        if plan_row:
            duration_days = int(plan_row["duration_days"])
            sub = set_subscription_active(wa_phone, plan, duration_days, reference, event_type)

            # Notify user in WhatsApp
            expires_at = sub.get("expires_at")
            msg = (
                "✅ Payment successful!\n\n"
                f"Your *{plan.upper()}* plan is now active.\n"
                f"📅 Valid until: {expires_at}\n\n"
                "Type MENU to continue."
            )
            send_whatsapp_text(wa_phone, msg)

    return jsonify({"ok": True})


# ------------------------------------------------------------
# Local dev
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
