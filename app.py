import os
import json
import hmac
import hashlib
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from supabase import create_client

app = Flask(__name__)

# --------------------------------------------------
# ENV
# --------------------------------------------------
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
META_APP_SECRET = os.getenv("META_APP_SECRET")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY")
BASE_URL = os.getenv("BASE_URL")  # koyeb public url

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --------------------------------------------------
# UTILITIES
# --------------------------------------------------
def verify_meta_signature(req):
    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    expected = hmac.new(
        META_APP_SECRET.encode(),
        req.data,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature.split("=")[1], expected)


def send_whatsapp(to, text):
    url = f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": text}
    }
    requests.post(url, headers=headers, json=payload)


# --------------------------------------------------
# HEALTH
# --------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    return "OK", 200


# --------------------------------------------------
# WEBHOOK (META)
# --------------------------------------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # ---- VERIFY
    if request.method == "GET":
        if (
            request.args.get("hub.mode") == "subscribe"
            and request.args.get("hub.verify_token") == VERIFY_TOKEN
        ):
            return request.args.get("hub.challenge"), 200
        return "Forbidden", 403

    # ---- SECURITY
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    data = request.get_json(force=True)

    # ---- DEDUP
    event_id = data.get("entry", [{}])[0].get("id")
    if event_id:
        exists = supabase.table("webhook_dedup").select("id").eq("id", event_id).execute()
        if exists.data:
            return jsonify({"status": "duplicate"}), 200
        supabase.table("webhook_dedup").insert({"id": event_id}).execute()

    try:
        msg = data["entry"][0]["changes"][0]["value"]["messages"][0]
        sender = msg["from"]
        text = msg.get("text", {}).get("body", "").strip().upper()

        supabase.table("wa_users").upsert({"wa_phone": sender}).execute()

        # ---- HELP MENU
        if text in ["HELP", "MENU", "START"]:
            send_whatsapp(
                sender,
                """📌 *Naija Tax Guide*

1️⃣ BASIC – ₦3,000 (30 days)
2️⃣ STANDARD – ₦8,000 (90 days)
3️⃣ PREMIUM – ₦30,000 (1 year)

Reply with:
BASIC
STANDARD
PREMIUM
"""
            )
            return jsonify({"status": "menu"}), 200

        # ---- SUBSCRIBE
        if text in ["BASIC", "STANDARD", "PREMIUM"]:
            plan = text.lower()

            plan_row = supabase.table("plans").select("*").eq("plan", plan).single().execute().data

            reference = f"NTG-{sender}-{int(datetime.utcnow().timestamp())}"

            supabase.table("payments").insert({
                "wa_phone": sender,
                "provider": "paystack",
                "reference": reference,
                "plan": plan,
                "amount_kobo": plan_row["amount_kobo"],
                "currency": "NGN",
                "status": "pending"
            }).execute()

            pay_url = init_paystack(reference, plan_row["amount_kobo"], sender)

            send_whatsapp(
                sender,
                f"💳 Pay to activate *{plan.upper()}*:\n{pay_url}"
            )
            return jsonify({"status": "payment_link"}), 200

        send_whatsapp(sender, "Reply HELP to continue.")

    except Exception as e:
        print("Webhook error:", e)

    return jsonify({"status": "ok"}), 200


# --------------------------------------------------
# PAYSTACK INIT
# --------------------------------------------------
def init_paystack(reference, amount, phone):
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET}",
        "Content-Type": "application/json"
    }
    payload = {
        "reference": reference,
        "amount": amount,
        "email": f"{phone}@naijatax.app",
        "callback_url": f"{BASE_URL}/paystack/callback"
    }
    r = requests.post(url, headers=headers, json=payload)
    return r.json()["data"]["authorization_url"]


# --------------------------------------------------
# PAYSTACK WEBHOOK
# --------------------------------------------------
@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    signature = request.headers.get("x-paystack-signature")

    computed = hmac.new(
        PAYSTACK_SECRET.encode(),
        request.data,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(signature, computed):
        return "Invalid", 403

    event = request.get_json()

    if event["event"] == "charge.success":
        ref = event["data"]["reference"]
        phone = event["data"]["customer"]["email"].split("@")[0]

        plan = supabase.table("payments").select("plan").eq("reference", ref).single().execute().data["plan"]
        duration = supabase.table("plans").select("duration_days").eq("plan", plan).single().execute().data["duration_days"]

        expires = datetime.utcnow() + timedelta(days=duration)

        supabase.table("user_subscriptions").upsert({
            "wa_phone": phone,
            "plan": plan,
            "status": "active",
            "expires_at": expires.isoformat(),
            "paystack_reference": ref,
            "last_event": "charge.success"
        }).execute()

        send_whatsapp(phone, f"✅ *{plan.upper()}* activated!\nExpires: {expires.date()}")

    return "OK", 200
