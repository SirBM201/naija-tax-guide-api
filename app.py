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
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
META_APP_SECRET = os.getenv("META_APP_SECRET", "")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY", "")
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")  # koyeb public url

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --------------------------------------------------
# UTILITIES
# --------------------------------------------------
def verify_meta_signature(req) -> bool:
    """
    Meta sends: X-Hub-Signature-256: sha256=...
    Only verify if META_APP_SECRET is set; otherwise fail closed.
    """
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

    provided = signature.split("=", 1)[1].strip()
    return hmac.compare_digest(provided, expected)


def send_whatsapp(to: str, text: str):
    """
    Sends a WhatsApp text message via Cloud API.
    Logs any errors to stdout (Koyeb logs).
    """
    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
        print("send_whatsapp: missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID")
        return

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

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code >= 300:
            print("send_whatsapp failed:", r.status_code, r.text)
        else:
            # Optional: print message id
            try:
                print("send_whatsapp ok:", r.json())
            except Exception:
                print("send_whatsapp ok (non-json response)")
    except Exception as e:
        print("send_whatsapp exception:", str(e))


def get_text_upper(msg: dict) -> str:
    text = (msg.get("text", {}) or {}).get("body", "")
    return (text or "").strip().upper()


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
    # ---- VERIFY (Meta setup will call this with hub.* params)
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
            return challenge, 200

        # If you open /webhook in a browser, you will see Forbidden (normal)
        return "Forbidden", 403

    # ---- SECURITY (signature)
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    data = request.get_json(silent=True) or {}
    # print("INCOMING:", json.dumps(data)[:1000])  # uncomment for debugging

    try:
        # Meta structure: entry -> changes -> value
        entry = (data.get("entry") or [{}])[0]
        changes = (entry.get("changes") or [{}])
        value = (changes[0].get("value") or {})

        # Sometimes Meta sends statuses updates, not messages
        messages = value.get("messages") or []

        if not messages:
            return jsonify({"status": "no_message_event"}), 200

        msg = messages[0]
        sender = msg.get("from")
        wa_message_id = msg.get("id")  # <-- this is what we deduplicate on

        if not sender or not wa_message_id:
            return jsonify({"status": "missing_sender_or_message_id"}), 200

        # ---- DEDUP (Supabase table uses message_id)
        exists = (
            supabase
            .table("webhook_dedup")
            .select("message_id")
            .eq("message_id", wa_message_id)
            .execute()
        )
        if exists.data:
            return jsonify({"status": "duplicate"}), 200

        supabase.table("webhook_dedup").insert({
            "message_id": wa_message_id
        }).execute()

        # ---- Save / ensure user exists
        # (Assumes wa_users has wa_phone column)
        supabase.table("wa_users").upsert({"wa_phone": sender}).execute()

        # ---- Parse text
        text = get_text_upper(msg)

        # ---- HELP MENU
        if text in ["HELP", "MENU", "START"]:
            send_whatsapp(
                sender,
                "📌 *Naija Tax Guide*\n\n"
                "1️⃣ BASIC – ₦3,000 (30 days)\n"
                "2️⃣ STANDARD – ₦8,000 (90 days)\n"
                "3️⃣ PREMIUM – ₦30,000 (1 year)\n\n"
                "Reply with:\n"
                "BASIC\nSTANDARD\nPREMIUM"
            )
            return jsonify({"status": "menu"}), 200

        # ---- SUBSCRIBE
        if text in ["BASIC", "STANDARD", "PREMIUM"]:
            plan = text.lower()

            plan_res = supabase.table("plans").select("*").eq("plan", plan).limit(1).execute()
            if not plan_res.data:
                send_whatsapp(sender, "⚠️ Plan not found. Reply HELP to see plans.")
                return jsonify({"status": "plan_missing"}), 200

            plan_row = plan_res.data[0]
            amount_kobo = int(plan_row["amount_kobo"])

            reference = f"NTG-{sender}-{int(datetime.utcnow().timestamp())}"

            supabase.table("payments").insert({
                "wa_phone": sender,
                "provider": "paystack",
                "reference": reference,
                "plan": plan,
                "amount_kobo": amount_kobo,
                "currency": "NGN",
                "status": "pending"
            }).execute()

            pay_url = init_paystack(reference, amount_kobo, sender)

            send_whatsapp(
                sender,
                f"💳 Pay to activate *{plan.upper()}*:\n{pay_url}"
            )
            return jsonify({"status": "payment_link"}), 200

        # Default response
        send_whatsapp(sender, "Reply HELP to continue.")
        return jsonify({"status": "default"}), 200

    except Exception as e:
        print("Webhook error:", str(e))
        return jsonify({"status": "error", "message": str(e)}), 200


# --------------------------------------------------
# PAYSTACK INIT
# --------------------------------------------------
def init_paystack(reference: str, amount_kobo: int, phone: str) -> str:
    """
    Paystack initialize expects amount in kobo.
    callback_url should be YOUR backend endpoint. No ?ref=REFERENCE is needed.
    """
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET}",
        "Content-Type": "application/json"
    }
    payload = {
        "reference": reference,
        "amount": amount_kobo,
        "email": f"{phone}@naijatax.app",
        "callback_url": f"{BASE_URL}/paystack/callback"
    }

    r = requests.post(url, headers=headers, json=payload, timeout=30)
    data = r.json()

    if r.status_code >= 300:
        raise RuntimeError(f"Paystack init failed: {r.status_code} {json.dumps(data)}")

    return data["data"]["authorization_url"]


# --------------------------------------------------
# PAYSTACK WEBHOOK
# --------------------------------------------------
@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    signature = request.headers.get("x-paystack-signature", "")

    computed = hmac.new(
        PAYSTACK_SECRET.encode("utf-8"),
        request.data,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(signature, computed):
        return "Invalid", 403

    event = request.get_json(silent=True) or {}

    try:
        if event.get("event") == "charge.success":
            data = event.get("data") or {}
            ref = data.get("reference")
            customer = data.get("customer") or {}
            email = customer.get("email", "")
            phone = email.split("@")[0] if "@" in email else None

            if not ref or not phone:
                return "OK", 200

            payment = (
                supabase.table("payments")
                .select("plan")
                .eq("reference", ref)
                .limit(1)
                .execute()
            )
            if not payment.data:
                return "OK", 200

            plan = payment.data[0]["plan"]

            plan_info = (
                supabase.table("plans")
                .select("duration_days")
                .eq("plan", plan)
                .limit(1)
                .execute()
            )
            if not plan_info.data:
                return "OK", 200

            duration = int(plan_info.data[0]["duration_days"])
            expires = datetime.utcnow() + timedelta(days=duration)

            supabase.table("user_subscriptions").upsert({
                "wa_phone": phone,
                "plan": plan,
                "status": "active",
                "expires_at": expires.isoformat(),
                "paystack_reference": ref,
                "last_event": "charge.success"
            }).execute()

            # also mark payment as paid
            supabase.table("payments").update({
                "status": "paid"
            }).eq("reference", ref).execute()

            send_whatsapp(phone, f"✅ *{plan.upper()}* activated!\nExpires: {expires.date()}")

        return "OK", 200

    except Exception as e:
        print("paystack_webhook error:", str(e))
        return "OK", 200


# --------------------------------------------------
# OPTIONAL: Paystack Callback endpoint (browser redirect)
# --------------------------------------------------
@app.route("/paystack/callback", methods=["GET"])
def paystack_callback():
    """
    Users are redirected here after payment.
    Real confirmation still comes from /paystack/webhook.
    """
    ref = request.args.get("reference", "")
    return f"Payment received. Reference: {ref}. You can return to WhatsApp.", 200
