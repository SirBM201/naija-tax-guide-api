import os
import hmac
import hashlib
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from supabase import create_client

app = Flask(__name__)

VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN") or os.getenv("VERIFY_TOKEN")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
META_APP_SECRET = os.getenv("META_APP_SECRET", "")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY")
BASE_URL = (os.getenv("BASE_URL") or "").rstrip("/")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def verify_meta_signature(req) -> bool:
    # If you haven't set META_APP_SECRET yet, don't block dev traffic
    if not META_APP_SECRET:
        return True

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    expected = hmac.new(
        META_APP_SECRET.encode("utf-8"),
        req.get_data(),
        hashlib.sha256
    ).hexdigest()

    provided = signature.split("=", 1)[1].strip()
    return hmac.compare_digest(provided, expected)

def send_whatsapp(to: str, text: str) -> bool:
    url = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": text}
    }
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code >= 400:
        print("send_whatsapp failed:", r.status_code, r.text)
        return False
    return True

def get_sender(payload: dict) -> str:
    return payload["entry"][0]["changes"][0]["value"]["messages"][0]["from"]

def get_message_id(payload: dict) -> str:
    return payload["entry"][0]["changes"][0]["value"]["messages"][0]["id"]

def get_text(payload: dict) -> str:
    msg = payload["entry"][0]["changes"][0]["value"]["messages"][0]
    if msg.get("type") == "text":
        return (msg.get("text", {}).get("body") or "").strip()
    if msg.get("type") == "interactive":
        inter = msg.get("interactive", {})
        itype = inter.get("type")
        if itype == "button_reply":
            return (inter.get("button_reply", {}).get("title") or "").strip()
        if itype == "list_reply":
            return (inter.get("list_reply", {}).get("title") or "").strip()
    return ""

def safe_log(kind: str, payload: dict):
    try:
        supabase.table("webhook_logs").insert({
            "kind": kind,
            "payload": payload,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
    except Exception:
        pass

@app.route("/", methods=["GET"])
def health():
    return "OK", 200

@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        # When you open /webhook directly in browser, just show OK
        if not mode:
            return "OK", 200

        if mode == "subscribe" and token == VERIFY_TOKEN:
            return challenge, 200

        return "Forbidden", 403

    # POST
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    data = request.get_json(silent=True) or {}
    safe_log("meta_webhook", data)

    # Ignore status-only events (no messages)
    try:
        value = data["entry"][0]["changes"][0]["value"]
        if "messages" not in value:
            return "EVENT_RECEIVED", 200
    except Exception:
        return "EVENT_RECEIVED", 200

    # Dedup by WhatsApp message id (and never crash webhook)
    try:
        msg_id = get_message_id(data)
        exists = supabase.table("webhook_dedup").select("id").eq("id", msg_id).execute()
        if getattr(exists, "data", None):
            return jsonify({"status": "duplicate"}), 200
        supabase.table("webhook_dedup").insert({"id": msg_id}).execute()
    except Exception as e:
        print("dedup skipped/error:", e)

    try:
        sender = get_sender(data)
        text = get_text(data).strip().upper()

        # Help menu
        if text in ["HELP", "MENU", "START", "HI", "HELLO"]:
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

        # Subscribe
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
                "status": "pending",
                "created_at": datetime.utcnow().isoformat()
            }).execute()

            pay_url = init_paystack(reference, plan_row["amount_kobo"], sender)

            send_whatsapp(sender, f"💳 Pay to activate *{plan.upper()}*:\n{pay_url}")
            return jsonify({"status": "payment_link"}), 200

        send_whatsapp(sender, "Reply HELP to continue.")
        return jsonify({"status": "fallback"}), 200

    except Exception as e:
        print("Webhook error:", e)
        return "EVENT_RECEIVED", 200

def init_paystack(reference, amount, phone):
    url = "https://api.paystack.co/transaction/initialize"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET}", "Content-Type": "application/json"}
    payload = {
        "reference": reference,
        "amount": int(amount),
        "email": f"{phone}@naijatax.app",
        "callback_url": f"{BASE_URL}/paystack/callback"
    }
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code >= 400:
        print("paystack init error:", r.status_code, r.text)
        raise RuntimeError("Paystack init failed")
    return r.json()["data"]["authorization_url"]

@app.route("/paystack/callback", methods=["GET"])
def paystack_callback():
    ref = request.args.get("reference") or request.args.get("trxref") or ""
    return f"Payment received. Activation is automatic. Ref: {ref}", 200

@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    signature = request.headers.get("x-paystack-signature", "")
    computed = hmac.new(
        PAYSTACK_SECRET.encode("utf-8"),
        request.get_data(),
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(signature, computed):
        return "Invalid", 403

    event = request.get_json(silent=True) or {}
    safe_log("paystack_webhook", event)

    if event.get("event") == "charge.success":
        ref = event["data"]["reference"]
        phone = event["data"]["customer"]["email"].split("@")[0]

        plan = supabase.table("payments").select("plan").eq("reference", ref).single().execute().data["plan"]
        duration = supabase.table("plans").select("duration_days").eq("plan", plan).single().execute().data["duration_days"]

        expires = datetime.utcnow() + timedelta(days=int(duration))

        supabase.table("user_subscriptions").upsert({
            "wa_phone": phone,
            "plan": plan,
            "status": "active",
            "expires_at": expires.isoformat(),
            "paystack_reference": ref,
            "last_event": "charge.success",
            "updated_at": datetime.utcnow().isoformat()
        }).execute()

        send_whatsapp(phone, f"✅ *{plan.upper()}* activated!\nExpires: {expires.date()}")

    return "OK", 200
