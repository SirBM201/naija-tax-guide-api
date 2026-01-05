import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta

import requests
from flask import Flask, request, jsonify
from supabase import create_client


# --------------------------------------------------
# APP + LOGGING
# --------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# --------------------------------------------------
# ENV (match your Koyeb variables)
# --------------------------------------------------
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")  # <-- IMPORTANT: match koyeb env name
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")  # or WHATSAPP_PHONE_NUMBER_ID in your env
META_APP_SECRET = os.getenv("META_APP_SECRET", "")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY", "")
BASE_URL = os.getenv("BASE_URL", os.getenv("APP_BASE_URL", "")).rstrip("/")

if not (SUPABASE_URL and SUPABASE_KEY):
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# --------------------------------------------------
# UTILITIES
# --------------------------------------------------
def verify_meta_signature(req) -> bool:
    """
    Verify Meta webhook signature.
    Header: X-Hub-Signature-256: sha256=...
    """
    if not META_APP_SECRET:
        # If you have not set it, do NOT block all requests silently.
        # Better to log and accept (or you will never receive messages).
        logging.warning("META_APP_SECRET not set - skipping signature verification.")
        return True

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    expected = hmac.new(
        META_APP_SECRET.encode("utf-8"),
        req.data,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature.split("=", 1)[1], expected)


def send_whatsapp(to: str, text: str) -> dict:
    """
    Send WhatsApp text message via Cloud API.
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

    r = requests.post(url, headers=headers, json=payload, timeout=30)

    # Log response for debugging delivery issues
    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text}

    logging.info(f"WA send status={r.status_code} response={data}")

    # Optional: store outbound responses in DB (if table exists)
    # If you created wa_delivery as shown in your SQL, this is useful.
    try:
        msg_id = data.get("messages", [{}])[0].get("id")
        supabase.table("wa_delivery").insert({
            "message_id": msg_id,
            "to_phone": to,
            "status": "sent" if r.ok else "failed",
            "raw_response": data
        }).execute()
    except Exception as e:
        logging.warning(f"wa_delivery insert skipped/failed: {e}")

    return data


def extract_inbound_message(payload: dict):
    """
    Extract sender phone + message text + message_id from Meta webhook payload.
    Returns: (sender, text_upper, message_id) or (None, None, None)
    """
    try:
        entry = payload["entry"][0]
        change = entry["changes"][0]
        value = change["value"]

        messages = value.get("messages", [])
        if not messages:
            return None, None, None

        msg = messages[0]
        sender = msg.get("from")
        message_id = msg.get("id")  # <-- THIS is the best dedup key
        text = msg.get("text", {}).get("body", "").strip()

        if not sender:
            return None, None, None

        return sender, (text or "").upper(), message_id
    except Exception:
        return None, None, None


def dedup_inbound(message_id: str) -> bool:
    """
    Returns True if duplicate (already processed), False if new.
    This matches your table schema: public.webhook_dedup(message_id, created_at)
    """
    if not message_id:
        return False

    # Check if already exists
    existing = supabase.table("webhook_dedup").select("message_id").eq("message_id", message_id).execute()
    if existing.data:
        return True

    # Insert new
    supabase.table("webhook_dedup").insert({"message_id": message_id}).execute()
    return False


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
    # ---- VERIFY (Meta webhook verification)
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
            return challenge, 200

        # When you open /webhook manually in browser, you'll see this.
        return "Forbidden", 403

    # ---- SECURITY
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    data = request.get_json(force=True, silent=True) or {}
    logging.info(f"Incoming webhook: {json.dumps(data)[:2000]}")  # truncate for logs

    # ---- Extract inbound
    sender, text, inbound_message_id = extract_inbound_message(data)

    # If this webhook is a status update (delivery/read) or something else, just ACK
    if not sender:
        return jsonify({"status": "ignored"}), 200

    # ---- DEDUP by WhatsApp inbound message_id
    try:
        if inbound_message_id and dedup_inbound(inbound_message_id):
            return jsonify({"status": "duplicate"}), 200
    except Exception as e:
        logging.error(f"Dedup failed: {e}")
        # Do not crash webhook; still proceed to respond.

    # Ensure user exists
    try:
        supabase.table("wa_users").upsert({"wa_phone": sender}).execute()
    except Exception as e:
        logging.warning(f"wa_users upsert failed: {e}")

    # ---- HELP MENU
    if text in ["HELP", "MENU", "START"]:
        send_whatsapp(
            sender,
            (
                "📌 *Naija Tax Guide*\n\n"
                "1️⃣ BASIC – ₦3,000 (30 days)\n"
                "2️⃣ STANDARD – ₦8,000 (90 days)\n"
                "3️⃣ PREMIUM – ₦30,000 (1 year)\n\n"
                "Reply with:\n"
                "BASIC\n"
                "STANDARD\n"
                "PREMIUM"
            )
        )
        return jsonify({"status": "menu"}), 200

    # ---- SUBSCRIBE
    if text in ["BASIC", "STANDARD", "PREMIUM"]:
        plan = text.lower()

        plan_row = supabase.table("plans").select("*").eq("plan", plan).single().execute().data
        if not plan_row:
            send_whatsapp(sender, "❌ Plan not found. Reply HELP to continue.")
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

        pay_url = init_paystack(reference, plan_row["amount_kobo"], sender)

        send_whatsapp(sender, f"💳 Pay to activate *{plan.upper()}*:\n{pay_url}")
        return jsonify({"status": "payment_link"}), 200

    # ---- DEFAULT
    send_whatsapp(sender, "Reply HELP to continue.")
    return jsonify({"status": "ok"}), 200


# --------------------------------------------------
# PAYSTACK INIT
# --------------------------------------------------
def init_paystack(reference: str, amount_kobo: int, phone: str) -> str:
    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET}",
        "Content-Type": "application/json",
    }
    payload = {
        "reference": reference,
        "amount": amount_kobo,
        "email": f"{phone}@naijatax.app",
        "callback_url": f"{BASE_URL}/paystack/callback",
        "metadata": {"wa_phone": phone},
    }
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    data = r.json()
    if not r.ok:
        raise RuntimeError(f"Paystack init failed: {data}")

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

    event = request.get_json(force=True) or {}
    logging.info(f"Paystack webhook: {json.dumps(event)[:2000]}")

    if event.get("event") == "charge.success":
        ref = event["data"]["reference"]

        # Prefer metadata wa_phone if present
        wa_phone = None
        try:
            wa_phone = event["data"].get("metadata", {}).get("wa_phone")
        except Exception:
            wa_phone = None

        # Fallback: parse email prefix
        if not wa_phone:
            email = event["data"]["customer"]["email"]
            wa_phone = email.split("@")[0]

        payment = supabase.table("payments").select("plan").eq("reference", ref).single().execute().data
        if not payment:
            return "OK", 200

        plan = payment["plan"]
        duration = supabase.table("plans").select("duration_days").eq("plan", plan).single().execute().data["duration_days"]

        expires = datetime.utcnow() + timedelta(days=int(duration))

        supabase.table("user_subscriptions").upsert({
            "wa_phone": wa_phone,
            "plan": plan,
            "status": "active",
            "expires_at": expires.isoformat(),
            "paystack_reference": ref,
            "last_event": "charge.success"
        }).execute()

        send_whatsapp(wa_phone, f"✅ *{plan.upper()}* activated!\nExpires: {expires.date()}")

    return "OK", 200
