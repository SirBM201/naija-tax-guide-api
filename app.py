import os
import json
import hmac
import hashlib
import requests
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify
from supabase import create_client

app = Flask(__name__)

# --------------------------------------------------
# ENV
# --------------------------------------------------
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
META_APP_SECRET = os.getenv("META_APP_SECRET", "")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "")  # your koyeb url, e.g. https://xxxx.koyeb.app

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# --------------------------------------------------
# UTILITIES
# --------------------------------------------------
def verify_meta_signature(req) -> bool:
    """Verify X-Hub-Signature-256 from Meta."""
    if not META_APP_SECRET:
        return False

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    expected = hmac.new(
        META_APP_SECRET.encode("utf-8"),
        req.data,
        hashlib.sha256
    ).hexdigest()

    received = signature.split("=", 1)[1]
    return hmac.compare_digest(received, expected)


def supa_insert_safe(table: str, data: dict):
    """Insert and ignore errors for best-effort logging."""
    try:
        return supabase.table(table).insert(data).execute()
    except Exception:
        return None


def ensure_user(wa_phone: str):
    supabase.table("wa_users").upsert({
        "wa_phone": wa_phone,
        "last_seen_at": datetime.now(timezone.utc).isoformat()
    }).execute()


def send_whatsapp(to_phone: str, text: str):
    """Send WhatsApp message and log response."""
    url = f"https://graph.facebook.com/v18.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": text}
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=20)
    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}

    # Log delivery attempt
    wa_msg_id = None
    if isinstance(data, dict):
        wa_msg_id = (
            data.get("messages", [{}])[0].get("id")
            if data.get("messages") else None
        )

    supa_insert_safe("wa_delivery", {
        "to_phone": to_phone,
        "direction": "out",
        "wa_message_id": wa_msg_id,
        "status": "sent" if resp.status_code < 300 else "failed",
        "payload": data
    })

    if resp.status_code >= 300:
        raise RuntimeError(f"WhatsApp send failed {resp.status_code}: {data}")

    return data


# --------------------------------------------------
# HEALTH
# --------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    return "OK", 200


# --------------------------------------------------
# WEBHOOK (META -> WhatsApp)
# --------------------------------------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # ---- VERIFY (Meta will call this when setting webhook)
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == WHATSAPP_VERIFY_TOKEN:
            return challenge, 200
        return "Forbidden", 403

    # ---- SECURITY (Meta signature)
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    data = request.get_json(force=True, silent=True) or {}
    supa_insert_safe("webhook_logs", {"source": "meta_whatsapp", "payload": data})

    try:
        value = data["entry"][0]["changes"][0]["value"]

        # WhatsApp message event
        if "messages" not in value:
            return jsonify({"status": "ignored"}), 200

        msg = value["messages"][0]
        sender = msg["from"]
        message_id = msg.get("id")

        ensure_user(sender)

        # ---- DEDUP using WhatsApp message_id
        if message_id:
            exists = (
                supabase.table("webhook_dedup")
                .select("message_id")
                .eq("message_id", message_id)
                .execute()
            )
            if exists.data:
                return jsonify({"status": "duplicate"}), 200

            supabase.table("webhook_dedup").insert({"message_id": message_id}).execute()

        # ---- Text handling
        text = (msg.get("text", {}).get("body") or "").strip().upper()

        if text in ["HELP", "MENU", "START"]:
            send_whatsapp(
                sender,
                (
                    "📌 *Naija Tax Guide*\n\n"
                    "1️⃣ BASIC – ₦3,000 (30 days)\n"
                    "2️⃣ STANDARD – ₦8,000 (90 days)\n"
                    "3️⃣ PREMIUM – ₦30,000 (1 year)\n\n"
                    "Reply with:\n"
                    "BASIC\nSTANDARD\nPREMIUM"
                )
            )
            return jsonify({"status": "menu"}), 200

        if text in ["BASIC", "STANDARD", "PREMIUM"]:
            plan = text.lower()

            plan_row = (
                supabase.table("plans")
                .select("*")
                .eq("plan", plan)
                .single()
                .execute()
                .data
            )
            if not plan_row:
                send_whatsapp(sender, "⚠️ Plan not found. Reply HELP.")
                return jsonify({"status": "plan_missing"}), 200

            reference = f"NTG-{sender}-{int(datetime.now(timezone.utc).timestamp())}"

            # Create payment record
            supabase.table("payments").insert({
                "reference": reference,
                "wa_phone": sender,
                "provider": "paystack",
                "plan": plan,
                "amount_kobo": int(plan_row["amount_kobo"]),
                "currency": plan_row.get("currency", "NGN"),
                "status": "pending"
            }).execute()

            pay_url = init_paystack(reference, int(plan_row["amount_kobo"]), sender)

            send_whatsapp(sender, f"💳 Pay to activate *{plan.upper()}*:\n{pay_url}")
            return jsonify({"status": "payment_link"}), 200

        send_whatsapp(sender, "Reply *HELP* to continue.")
        return jsonify({"status": "ok"}), 200

    except Exception as e:
        supa_insert_safe("webhook_logs", {"source": "meta_whatsapp_error", "payload": {"error": str(e), "data": data}})
        return jsonify({"status": "error", "message": str(e)}), 200


# --------------------------------------------------
# PAYSTACK INIT
# --------------------------------------------------
def init_paystack(reference: str, amount_kobo: int, phone: str) -> str:
    if not PAYSTACK_SECRET_KEY:
        raise RuntimeError("Missing PAYSTACK_SECRET_KEY")

    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "reference": reference,
        "amount": amount_kobo,
        "email": f"{phone}@naijatax.app",
        "callback_url": f"{APP_BASE_URL}/paystack/callback"
    }

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    data = r.json()

    if r.status_code >= 300 or not data.get("status"):
        raise RuntimeError(f"Paystack init failed: {data}")

    return data["data"]["authorization_url"]


# --------------------------------------------------
# PAYSTACK CALLBACK (optional)
# --------------------------------------------------
@app.route("/paystack/callback", methods=["GET"])
def paystack_callback():
    return "Payment received. You can return to WhatsApp.", 200


# --------------------------------------------------
# PAYSTACK WEBHOOK
# --------------------------------------------------
@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    signature = request.headers.get("x-paystack-signature", "")
    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        request.data,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(signature, computed):
        return "Invalid", 403

    event = request.get_json(force=True, silent=True) or {}
    supa_insert_safe("webhook_logs", {"source": "paystack", "payload": event})

    if event.get("event") == "charge.success":
        ref = event["data"]["reference"]
        customer_email = event["data"]["customer"]["email"]
        phone = customer_email.split("@")[0]

        # Update payments
        supabase.table("payments").update({
            "status": "success",
            "paid_at": datetime.now(timezone.utc).isoformat(),
            "raw_event": event
        }).eq("reference", ref).execute()

        # Determine plan duration
        pay_row = supabase.table("payments").select("plan").eq("reference", ref).single().execute().data
        plan = pay_row["plan"]

        duration = supabase.table("plans").select("duration_days").eq("plan", plan).single().execute().data["duration_days"]
        expires = datetime.now(timezone.utc) + timedelta(days=int(duration))

        # Upsert subscription
        supabase.table("user_subscriptions").upsert({
            "wa_phone": phone,
            "plan": plan,
            "status": "active",
            "expires_at": expires.isoformat(),
            "paystack_reference": ref,
            "last_event": "charge.success",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }).execute()

        send_whatsapp(phone, f"✅ *{plan.upper()}* activated!\nExpires: {expires.date()}")

    return "OK", 200
