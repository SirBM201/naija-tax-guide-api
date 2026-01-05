import os
import json
import hmac
import hashlib
import logging
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from supabase import create_client

# --------------------------------------------------
# APP
# --------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# --------------------------------------------------
# ENV
# --------------------------------------------------
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")  # must match Meta Webhook verify token
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")
META_APP_SECRET = os.getenv("META_APP_SECRET", "")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY", "")
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")  # koyeb public url

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in env")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# --------------------------------------------------
# UTILITIES
# --------------------------------------------------
def verify_meta_signature(req) -> bool:
    """
    Verify Meta webhook signature (X-Hub-Signature-256).
    If META_APP_SECRET is not set, we fail closed (return False).
    """
    if not META_APP_SECRET:
        logging.error("META_APP_SECRET missing. Cannot verify signature.")
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


def send_whatsapp(to: str, text: str) -> dict:
    """
    Send a WhatsApp text message using Cloud API.
    Returns response JSON for debugging.
    """
    url = f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": text},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}

        if r.status_code >= 300:
            logging.error("WhatsApp send failed: %s %s", r.status_code, data)
        else:
            logging.info("WhatsApp sent OK: %s", data)

        return data
    except Exception as e:
        logging.exception("WhatsApp send exception: %s", e)
        return {"error": str(e)}


def init_paystack(reference: str, amount_kobo: int, phone: str) -> str:
    """
    Create Paystack payment link.
    """
    if not PAYSTACK_SECRET:
        raise RuntimeError("PAYSTACK_SECRET_KEY missing in env")
    if not BASE_URL:
        raise RuntimeError("BASE_URL missing in env (must be your Koyeb public URL)")

    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET}",
        "Content-Type": "application/json",
    }
    payload = {
        "reference": reference,
        "amount": int(amount_kobo),
        "email": f"{phone}@naijatax.app",
        "callback_url": f"{BASE_URL}/paystack/callback",
    }

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    data = r.json()

    if r.status_code >= 300 or not data.get("status"):
        raise RuntimeError(f"Paystack init failed: {data}")

    return data["data"]["authorization_url"]


def _extract_whatsapp_message(payload: dict):
    """
    Safely extract WhatsApp message fields from Meta webhook payload.
    Returns None if this is a status-only update or unsupported event.
    """
    try:
        entry = payload.get("entry", [])[0]
        changes = entry.get("changes", [])[0]
        value = changes.get("value", {})

        # If this payload has no messages, it's usually a status update (delivery/read)
        messages = value.get("messages", [])
        if not messages:
            return None

        msg = messages[0]
        msg_id = msg.get("id")                 # WhatsApp message unique id
        sender = msg.get("from")              # sender phone (wa id)
        text = (msg.get("text", {}) or {}).get("body", "")
        return {
            "msg_id": msg_id,
            "sender": sender,
            "text": text,
        }
    except Exception:
        return None


# --------------------------------------------------
# HEALTH
# --------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    return "OK", 200


# --------------------------------------------------
# WEBHOOK (META / WHATSAPP)
# --------------------------------------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # --------------- VERIFY (GET)
    if request.method == "GET":
        mode = request.args.get("hub.mode", "")
        token = request.args.get("hub.verify_token", "")
        challenge = request.args.get("hub.challenge", "")

        if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
            return challenge, 200

        return "Forbidden", 403

    # --------------- SECURITY (POST)
    # Meta sends webhook to /webhook with signature header
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    data = request.get_json(silent=True) or {}
    logging.info("Webhook received: %s", json.dumps(data)[:1500])

    # --------------- Parse message (ignore status-only callbacks)
    extracted = _extract_whatsapp_message(data)
    if not extracted:
        # Status updates should still return 200 to stop retries
        return jsonify({"status": "ignored_non_message"}), 200

    msg_id = extracted["msg_id"]
    sender = extracted["sender"]
    incoming_text = (extracted["text"] or "").strip()

    if not msg_id or not sender:
        return jsonify({"status": "ignored_missing_fields"}), 200

    # --------------- DEDUP (IMPORTANT FIX: use webhook_dedup.message_id)
    try:
        exists = (
            supabase.table("webhook_dedup")
            .select("message_id")
            .eq("message_id", msg_id)
            .execute()
        )
        if exists.data:
            return jsonify({"status": "duplicate"}), 200

        supabase.table("webhook_dedup").insert({"message_id": msg_id}).execute()
    except Exception as e:
        # If dedup table misconfigured, don't crash webhook (return 200)
        logging.exception("Dedup error (webhook_dedup): %s", e)

    # --------------- Ensure user exists
    try:
        supabase.table("wa_users").upsert({"wa_phone": sender}).execute()
    except Exception as e:
        logging.exception("wa_users upsert failed: %s", e)

    # --------------- Command handling
    text_upper = incoming_text.upper()

    # HELP MENU
    if text_upper in ["HELP", "MENU", "START"]:
        send_whatsapp(
            sender,
            "📌 *Naija Tax Guide*\n\n"
            "1️⃣ BASIC – ₦3,000 (30 days)\n"
            "2️⃣ STANDARD – ₦8,000 (90 days)\n"
            "3️⃣ PREMIUM – ₦30,000 (1 year)\n\n"
            "Reply with:\n"
            "BASIC\n"
            "STANDARD\n"
            "PREMIUM"
        )
        return jsonify({"status": "menu"}), 200

    # SUBSCRIBE FLOW
    if text_upper in ["BASIC", "STANDARD", "PREMIUM"]:
        plan = text_upper.lower()

        try:
            plan_row = (
                supabase.table("plans")
                .select("*")
                .eq("plan", plan)
                .single()
                .execute()
                .data
            )
            if not plan_row:
                send_whatsapp(sender, "⚠️ Plan not found. Reply HELP to see plans.")
                return jsonify({"status": "plan_missing"}), 200

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

            pay_url = init_paystack(reference, int(plan_row["amount_kobo"]), sender)

            send_whatsapp(sender, f"💳 Pay to activate *{plan.upper()}*:\n{pay_url}")
            return jsonify({"status": "payment_link"}), 200

        except Exception as e:
            logging.exception("Subscription flow error: %s", e)
            send_whatsapp(sender, "⚠️ Something went wrong creating payment link. Try again later.")
            return jsonify({"status": "error_subscribe"}), 200

    # Default response
    send_whatsapp(sender, "Reply HELP to continue.")
    return jsonify({"status": "ok"}), 200


# --------------------------------------------------
# PAYSTACK WEBHOOK
# --------------------------------------------------
@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    # Verify Paystack signature
    signature = request.headers.get("x-paystack-signature", "")
    computed = hmac.new(
        PAYSTACK_SECRET.encode("utf-8"),
        request.data,
        hashlib.sha512
    ).hexdigest()

    if not signature or not hmac.compare_digest(signature, computed):
        return "Invalid", 403

    event = request.get_json(silent=True) or {}
    logging.info("Paystack webhook: %s", json.dumps(event)[:1500])

    try:
        if event.get("event") == "charge.success":
            ref = event["data"]["reference"]
            email = event["data"]["customer"]["email"]
            phone = email.split("@")[0]

            payment = (
                supabase.table("payments")
                .select("plan")
                .eq("reference", ref)
                .single()
                .execute()
                .data
            )
            if not payment:
                return "OK", 200

            plan = payment["plan"]

            duration_row = (
                supabase.table("plans")
                .select("duration_days")
                .eq("plan", plan)
                .single()
                .execute()
                .data
            )
            duration_days = int(duration_row["duration_days"]) if duration_row else 30
            expires = datetime.utcnow() + timedelta(days=duration_days)

            supabase.table("user_subscriptions").upsert({
                "wa_phone": phone,
                "plan": plan,
                "status": "active",
                "expires_at": expires.isoformat(),
                "paystack_reference": ref,
                "last_event": "charge.success"
            }).execute()

            # Mark payment as success (optional but recommended)
            supabase.table("payments").update({
                "status": "success"
            }).eq("reference", ref).execute()

            send_whatsapp(phone, f"✅ *{plan.upper()}* activated!\nExpires: {expires.date()}")

    except Exception as e:
        logging.exception("Paystack handler error: %s", e)

    return "OK", 200


# --------------------------------------------------
# PAYSTACK CALLBACK (OPTIONAL)
# --------------------------------------------------
@app.route("/paystack/callback", methods=["GET"])
def paystack_callback():
    # Paystack redirects here after payment.
    # You can show a simple message. Activation is done by /paystack/webhook.
    ref = request.args.get("reference") or request.args.get("trxref") or ""
    return f"Payment received. Reference: {ref}. You can return to WhatsApp.", 200
