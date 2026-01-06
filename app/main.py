import os
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, request, jsonify, abort
from supabase import create_client

app = Flask(__name__)

# -----------------------------
# ENV
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")  # MUST match Meta verify token exactly
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

APP_PUBLIC_BASE_URL = os.getenv("APP_PUBLIC_BASE_URL", "").rstrip("/")
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "info@thecre8hub.com")
SUPPORT_PHONE = os.getenv("SUPPORT_PHONE", "+2347034941158")

# Pricing in kobo (NGN)
PLAN_PRICES_KOBO = {
    "monthly": 3000 * 100,
    "quarterly": 8000 * 100,
    "yearly": 30000 * 100,
}

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
    return str(raw).strip().replace("+", "").replace(" ", "")


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
    if not (WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID):
        return

    url = f"https://graph.facebook.com/v20.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text},
    }
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    try:
        requests.post(url, headers=headers, json=payload, timeout=15)
    except Exception:
        pass


def safe_json() -> Dict[str, Any]:
    try:
        return request.get_json(force=True, silent=True) or {}
    except Exception:
        return {}


def upsert_user(wa_phone: str) -> Dict[str, Any]:
    wa_phone = parse_wa_phone(wa_phone)

    res = supabase.table("users").select("*").eq("wa_phone", wa_phone).limit(1).execute()
    if res.data:
        user = res.data[0]
        supabase.table("users").update({"last_seen_at": now_utc().isoformat()}).eq("id", user["id"]).execute()
        return user

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
    sub = get_active_subscription(user_id)
    if not sub:
        return

    end_at = sub.get("end_at")
    if not end_at:
        return

    end_dt = datetime.fromisoformat(str(end_at).replace("Z", "+00:00"))
    if now_utc() >= end_dt:
        supabase.table("subscriptions").update({"status": "expired"}).eq("id", sub["id"]).execute()


def is_subscribed(user_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    expire_if_needed(user_id)
    sub = get_active_subscription(user_id)
    return (sub is not None, sub)


def make_pay_link_payload(wa_phone: str, plan: str, email: str) -> Dict[str, Any]:
    if plan not in PLAN_PRICES_KOBO:
        raise ValueError("Invalid plan")

    payload = {
        "email": email,
        "amount": PLAN_PRICES_KOBO[plan],
        "currency": "NGN",
        "reference": f"NTG_{wa_phone}_{int(now_utc().timestamp())}",
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "product": "Naija Tax Guide",
        },
    }

    if APP_PUBLIC_BASE_URL:
        payload["callback_url"] = f"{APP_PUBLIC_BASE_URL}/payment-success"

    return payload


# -----------------------------
# Routes
# -----------------------------
@app.get("/health")
def health():
    # Use this to keep the service warm if needed
    return jsonify({"ok": True, "service": "naija-tax-guide-api"}), 200


# =========================================================
# WhatsApp webhook (verification + inbound)
# =========================================================
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # ---- META VERIFICATION ----
    if request.method == "GET":
        mode = request.args.get("hub.mode", "")
        token = request.args.get("hub.verify_token", "")
        challenge = request.args.get("hub.challenge", "")

        # If your env var is empty, verification will ALWAYS fail
        if not WHATSAPP_VERIFY_TOKEN:
            return abort(500, description="WHATSAPP_VERIFY_TOKEN is missing in env vars")

        if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
            # Must return the raw challenge only
            return str(challenge), 200

        return abort(403)

    # ---- INBOUND EVENTS ----
    payload = safe_json()

    try:
        entry = (payload.get("entry") or [])[0]
        changes = (entry.get("changes") or [])[0]
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            return jsonify({"ok": True}), 200

        msg = messages[0]
        from_phone = msg.get("from", "")
        text = (msg.get("text") or {}).get("body", "").strip()

        if not from_phone:
            return jsonify({"ok": True}), 200

        user = upsert_user(from_phone)
        user_id = user["id"]

        subscribed, _sub = is_subscribed(user_id)

        if not subscribed:
            reply = (
                "Welcome to Naija Tax Guide.\n\n"
                "To continue, subscribe:\n"
                "1) Monthly – ₦3,000\n"
                "2) Quarterly – ₦8,000\n"
                "3) Yearly – ₦30,000\n\n"
                "Reply with: monthly / quarterly / yearly"
            )

            plan = text.lower()
            if plan in PLAN_PRICES_KOBO:
                email = f"{parse_wa_phone(from_phone)}@naijatax.local"
                init = create_paystack_transaction(parse_wa_phone(from_phone), plan, email)
                reply = (
                    f"Great. Click to pay for {plan} plan:\n{init['authorization_url']}\n\n"
                    "After payment, your subscription activates automatically."
                )

            send_whatsapp_message(parse_wa_phone(from_phone), reply)
            return jsonify({"ok": True}), 200

        if text.lower() in ("help", "menu"):
            send_whatsapp_message(
                parse_wa_phone(from_phone),
                "You are active.\nSend your tax question now, or type MENU anytime."
            )
            return jsonify({"ok": True}), 200

        send_whatsapp_message(
            parse_wa_phone(from_phone),
            "Received. Your request is being processed.\n\n(Next step: connect your Tax Q&A engine here.)"
        )
        return jsonify({"ok": True}), 200

    except Exception:
        # Always 200 to prevent retry storms
        return jsonify({"ok": True}), 200


# =========================================================
# Paystack Initialize
# =========================================================
def create_paystack_transaction(wa_phone: str, plan: str, email: str) -> Dict[str, Any]:
    wa_phone = parse_wa_phone(wa_phone)
    plan = plan.lower().strip()

    if plan not in PLAN_PRICES_KOBO:
        raise ValueError("Invalid plan")

    user = upsert_user(wa_phone)

    payload = make_pay_link_payload(wa_phone, plan, email)
    r = requests.post(
        "https://api.paystack.co/transaction/initialize",
        headers=paystack_headers(),
        data=json.dumps(payload),
        timeout=20,
    )
    data = r.json()
    if not data.get("status"):
        raise RuntimeError(data.get("message", "Paystack initialize failed"))

    ref = data["data"]["reference"]

    # NOTE: your DB screenshot shows subscriptions table might not have amount_kobo
    # We will insert ONLY what we know is safe. (You can add amount_kobo later if you want.)
    supabase.table("subscriptions").insert({
        "user_id": user["id"],
        "plan": plan,
        "status": "pending",
        "paystack_ref": ref,
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
        return jsonify({"ok": True, **result}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


# =========================================================
# Paystack Webhook (activate subscription)
# =========================================================
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data()
    signature = request.headers.get("x-paystack-signature", "")

    if not verify_paystack_signature(raw, signature):
        return "Invalid signature", 401

    event = request.get_json(force=True, silent=True) or {}
    event_type = event.get("event", "")
    data = event.get("data", {}) or {}

    if event_type not in ("charge.success",):
        return jsonify({"ok": True}), 200

    reference = data.get("reference")
    paid = data.get("status") == "success"

    if not reference or not paid:
        return jsonify({"ok": True}), 200

    sub_res = (
        supabase.table("subscriptions")
        .select("*")
        .eq("paystack_ref", reference)
        .limit(1)
        .execute()
    )
    if not sub_res.data:
        return jsonify({"ok": True}), 200

    sub = sub_res.data[0]
    plan = sub["plan"]
    user_id = sub["user_id"]

    supabase.table("subscriptions").update({"status": "expired"}).eq("user_id", user_id).eq("status", "active").execute()

    start_at = now_utc()
    end_at = start_at + timedelta(days=PLAN_DAYS.get(plan, 30))

    supabase.table("subscriptions").update({
        "status": "active",
        "start_at": start_at.isoformat(),
        "end_at": end_at.isoformat(),
    }).eq("id", sub["id"]).execute()

    user = supabase.table("users").select("wa_phone").eq("id", user_id).limit(1).execute()
    if user.data:
        wa_phone = user.data[0]["wa_phone"]
        send_whatsapp_message(
            wa_phone,
            f"Payment confirmed. Your {plan} subscription is now ACTIVE.\n"
            f"Valid until: {end_at.strftime('%Y-%m-%d')}\n\n"
            "You can now send your tax questions."
        )

    return jsonify({"ok": True}), 200


# =========================================================
# Optional: Daily Expiry Endpoint (hit with cron)
# =========================================================
@app.post("/cron/expire")
def cron_expire():
    secret = request.headers.get("x-cron-secret", "")
    expected = os.getenv("CRON_SECRET", "")
    if expected and secret != expected:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    now_iso = now_utc().isoformat()
    res = (
        supabase.table("subscriptions")
        .select("id")
        .eq("status", "active")
        .lt("end_at", now_iso)
        .execute()
    )
    if res.data:
        ids = [r["id"] for r in res.data]
        supabase.table("subscriptions").update({"status": "expired"}).in_("id", ids).execute()

    return jsonify({"ok": True, "expired_count": len(res.data or [])}), 200


# =========================================================
# Admin read endpoint
# =========================================================
@app.get("/admin/users")
def admin_users():
    key = request.headers.get("x-admin-key", "")
    expected = os.getenv("ADMIN_KEY", "")
    if expected and key != expected:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    status = request.args.get("status")
    q = supabase.table("v_admin_users").select("*").order("created_at", desc=True).limit(200)
    if status:
        q = q.eq("subscription_status", status)
    data = q.execute().data
    return jsonify({"ok": True, "data": data}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
