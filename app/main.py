import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone, date
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, request, jsonify
from supabase import create_client

# ------------------------------------------------------------
# App + Logging
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("naija-tax-guide-api")

# -----------------------------
# ENV
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

APP_PUBLIC_BASE_URL = os.getenv("APP_PUBLIC_BASE_URL", "").rstrip("/")
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "info@thecre8hub.com")
SUPPORT_PHONE = os.getenv("SUPPORT_PHONE", "+2347034941158")

# Basic safety limits (MVP defaults; we can tune later)
FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "10"))
PAID_DAILY_LIMIT = int(os.getenv("PAID_DAILY_LIMIT", "80"))
AI_DAILY_LIMIT_FREE = int(os.getenv("AI_DAILY_LIMIT_FREE", "3"))
AI_DAILY_LIMIT_PAID = int(os.getenv("AI_DAILY_LIMIT_PAID", "20"))

# Simple anti-spam: seconds between messages from same number
MIN_SECONDS_BETWEEN_MSGS = int(os.getenv("MIN_SECONDS_BETWEEN_MSGS", "3"))

ALLOWED_PLANS = {"monthly", "quarterly", "yearly"}

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")

if not PAYSTACK_SECRET_KEY:
    log.warning("PAYSTACK_SECRET_KEY is missing. /paystack/initialize will fail until set.")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()

def parse_iso(s: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None

def parse_wa_phone(raw: str) -> str:
    return raw.strip().replace("+", "").replace(" ", "")

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    if not signature or not PAYSTACK_WEBHOOK_SECRET:
        return False
    mac = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(mac, signature)

def safe_json() -> Dict[str, Any]:
    try:
        return request.get_json(force=True, silent=True) or {}
    except Exception:
        return {}

def send_whatsapp_message(to_phone: str, text: str) -> None:
    if not (WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID):
        log.warning("WhatsApp credentials missing. Skipping send.")
        return

    to_phone = parse_wa_phone(to_phone)
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
        r = requests.post(url, headers=headers, json=payload, timeout=15)
        if r.status_code >= 300:
            log.warning("WA send failed %s: %s", r.status_code, r.text[:500])
    except Exception as e:
        log.exception("WA send exception: %s", e)

# ------------------------------------------------------------
# DB: Users
# ------------------------------------------------------------
def upsert_user(wa_phone: str) -> Dict[str, Any]:
    wa_phone = parse_wa_phone(wa_phone)

    res = supabase.table("users").select("*").eq("wa_phone", wa_phone).limit(1).execute()
    if res.data:
        user = res.data[0]
        supabase.table("users").update({"last_seen_at": iso(now_utc())}).eq("id", user["id"]).execute()
        return user

    created = supabase.table("users").insert({
        "wa_phone": wa_phone,
        "state": "idle",
        "last_seen_at": iso(now_utc()),
    }).execute()
    return created.data[0]

# ------------------------------------------------------------
# DB: Plans (single source of truth)
# public.plans columns:
# - plan (text): monthly/quarterly/yearly
# - amount_kobo (int)
# - currency (text)
# - duration_days (int)
# ------------------------------------------------------------
def get_plan_row(plan: str) -> Dict[str, Any]:
    plan = (plan or "").strip().lower()
    if plan not in ALLOWED_PLANS:
        raise ValueError("Invalid plan. Use monthly / quarterly / yearly")

    res = (
        supabase.table("plans")
        .select("plan,title,amount_kobo,currency,duration_days")
        .eq("plan", plan)
        .single()
        .execute()
    )
    row = res.data
    if not row:
        raise ValueError(f"Plan not found in DB: {plan}")

    if row.get("amount_kobo") is None:
        raise ValueError(f"Plan has no amount_kobo: {plan}")

    if row.get("duration_days") is None:
        raise ValueError(f"Plan has no duration_days: {plan}")

    row["amount_kobo"] = int(row["amount_kobo"])
    row["duration_days"] = int(row["duration_days"])
    row["currency"] = row.get("currency") or "NGN"
    return row

# ------------------------------------------------------------
# DB: Subscriptions (single source of truth)
# public.subscriptions columns:
# id, user_id, plan, status, start_at, end_at, paystack_ref, updated_at, amount_kobo, currency
# ------------------------------------------------------------
def get_active_subscription(user_id: str) -> Optional[Dict[str, Any]]:
    res = (
        supabase.table("subscriptions")
        .select("*")
        .eq("user_id", user_id)
        .eq("status", "active")
        .order("updated_at", desc=True)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None

def expire_if_needed(user_id: str) -> None:
    sub = get_active_subscription(user_id)
    if not sub:
        return
    end_at = sub.get("end_at")
    if not end_at:
        return
    end_dt = parse_iso(end_at)
    if end_dt and now_utc() >= end_dt:
        supabase.table("subscriptions").update({"status": "expired"}).eq("id", sub["id"]).execute()

def is_subscribed(user_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    expire_if_needed(user_id)
    sub = get_active_subscription(user_id)
    return (sub is not None, sub)

# ------------------------------------------------------------
# Abuse controls (MVP)
# We'll store daily usage in a simple table if you create it later.
# For now, we will do a lightweight per-user pacing using users.last_seen_at.
# ------------------------------------------------------------
def too_fast(user: Dict[str, Any]) -> bool:
    last = user.get("last_seen_at")
    if not last:
        return False
    dt = parse_iso(last)
    if not dt:
        return False
    return (now_utc() - dt).total_seconds() < MIN_SECONDS_BETWEEN_MSGS

# ------------------------------------------------------------
# Paystack initialize payload
# ------------------------------------------------------------
def make_pay_link_payload(wa_phone: str, plan: str, email: str) -> Dict[str, Any]:
    plan_row = get_plan_row(plan)

    payload = {
        "email": email,
        "amount": plan_row["amount_kobo"],  # already kobo
        "currency": plan_row["currency"],
        "reference": f"NTG_{wa_phone}_{int(now_utc().timestamp())}",
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "product": "Naija Tax Guide",
        },
    }

    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL
    elif APP_PUBLIC_BASE_URL:
        payload["callback_url"] = f"{APP_PUBLIC_BASE_URL}/payment-success"

    return payload

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/")
def index():
    return jsonify({
        "ok": True,
        "service": "naija-tax-guide-api",
        "routes": ["/health", "/webhook", "/paystack/initialize", "/paystack/webhook"],
    })

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

    log.info("WA verify: mode=%s token_match=%s", mode, token == WHATSAPP_VERIFY_TOKEN)

    if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200
    return "Forbidden", 403

@app.post("/webhook")
def whatsapp_inbound():
    payload = safe_json()

    try:
        entry = (payload.get("entry") or [])[0]
        changes = (entry.get("changes") or [])[0]
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            return jsonify({"ok": True})

        msg = messages[0]
        from_phone = msg.get("from", "")
        text = (msg.get("text") or {}).get("body", "").strip()
        if not from_phone:
            return jsonify({"ok": True})

        user = upsert_user(from_phone)
        if too_fast(user):
            return jsonify({"ok": True})

        user_id = user["id"]
        subscribed, _ = is_subscribed(user_id)

        # Not subscribed => subscription prompt + payment link
        if not subscribed:
            reply = (
                "Welcome to Naija Tax Guide.\n\n"
                "To continue, subscribe:\n"
                "1) Monthly – ₦3,000\n"
                "2) Quarterly – ₦8,000\n"
                "3) Yearly – ₦30,000\n\n"
                "Reply with: monthly / quarterly / yearly"
            )

            plan = text.lower().strip()
            if plan in ALLOWED_PLANS:
                email = f"{parse_wa_phone(from_phone)}@naijatax.local"
                init = create_paystack_transaction(parse_wa_phone(from_phone), plan, email)
                reply = (
                    f"Great. Click to pay for {plan} plan:\n{init['authorization_url']}\n\n"
                    "After payment, your subscription activates automatically."
                )

            send_whatsapp_message(parse_wa_phone(from_phone), reply)
            return jsonify({"ok": True})

        # subscribed user flow (placeholder for Q&A engine)
        if text.lower() in ("help", "menu"):
            send_whatsapp_message(parse_wa_phone(from_phone),
                "You are active.\nSend your tax question now, or type MENU anytime."
            )
            return jsonify({"ok": True})

        send_whatsapp_message(parse_wa_phone(from_phone),
            "Received. Your request is being processed.\n\n(Next step: FAQ + AI engine integration.)"
        )
        return jsonify({"ok": True})

    except Exception as e:
        log.exception("WA inbound exception: %s", e)
        return jsonify({"ok": True})

# =========================================================
# Paystack Initialize
# =========================================================
def create_paystack_transaction(wa_phone: str, plan: str, email: str) -> Dict[str, Any]:
    wa_phone = parse_wa_phone(wa_phone)
    plan = plan.lower().strip()

    if not PAYSTACK_SECRET_KEY:
        raise RuntimeError("PAYSTACK_SECRET_KEY missing")
    if plan not in ALLOWED_PLANS:
        raise ValueError("Invalid plan. Use monthly / quarterly / yearly")

    user = upsert_user(wa_phone)
    plan_row = get_plan_row(plan)

    payload = make_pay_link_payload(wa_phone, plan, email)

    r = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers=paystack_headers(),
        data=json.dumps(payload),
        timeout=20
    )

    data = r.json() if r.content else {}
    if not data.get("status"):
        raise RuntimeError(data.get("message", "Paystack initialize failed"))

    ref = data["data"]["reference"]

    # Create a pending subscription row
    # NOTE: paystack_ref is UNIQUE, so repeated calls with same ref won't duplicate
    supabase.table("subscriptions").insert({
        "user_id": user["id"],
        "plan": plan,
        "status": "pending",
        "paystack_ref": ref,
        "amount_kobo": plan_row["amount_kobo"],
        "currency": plan_row["currency"],
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
    raw = request.get_data() or b""
    signature = request.headers.get("x-paystack-signature", "")

    if not verify_paystack_signature(raw, signature):
        return "Invalid signature", 401

    event = request.get_json(force=True, silent=True) or {}
    event_type = event.get("event", "")
    data = event.get("data", {}) or {}

    # Log minimal info for debugging (safe)
    ref = (data.get("reference") or "")
    log.info("Paystack webhook: event=%s ref=%s", event_type, ref)

    if event_type != "charge.success":
        return jsonify({"ok": True})

    if (data.get("status") != "success"):
        return jsonify({"ok": True})

    reference = data.get("reference")
    if not reference:
        return jsonify({"ok": True})

    # Find subscription by reference
    sub_res = (
        supabase.table("subscriptions")
        .select("*")
        .eq("paystack_ref", reference)
        .limit(1)
        .execute()
    )
    if not sub_res.data:
        return jsonify({"ok": True})

    sub = sub_res.data[0]
    if sub.get("status") == "active":
        return jsonify({"ok": True})

    plan = sub.get("plan")
    user_id = sub.get("user_id")
    if not plan or not user_id:
        return jsonify({"ok": True})

    plan_row = get_plan_row(plan)
    duration_days = plan_row["duration_days"]

    # Expire any other active subscription
    supabase.table("subscriptions").update({"status": "expired"}).eq("user_id", user_id).eq("status", "active").execute()

    start_at = now_utc()
    end_at = start_at + timedelta(days=int(duration_days))

    supabase.table("subscriptions").update({
        "status": "active",
        "start_at": iso(start_at),
        "end_at": iso(end_at),
        "amount_kobo": plan_row["amount_kobo"],
        "currency": plan_row["currency"],
        "updated_at": iso(now_utc()),
    }).eq("id", sub["id"]).execute()

    # WhatsApp notify
    user_res = supabase.table("users").select("wa_phone").eq("id", user_id).limit(1).execute()
    if user_res.data:
        wa_phone = user_res.data[0]["wa_phone"]
        send_whatsapp_message(wa_phone,
            f"Payment confirmed. Your {plan} subscription is now ACTIVE.\n"
            f"Valid until: {end_at.strftime('%Y-%m-%d')}\n\n"
            "You can now send your tax questions."
        )

    return jsonify({"ok": True})

# ------------------------------------------------------------
# Run
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
