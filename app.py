import os
import json
import hmac
import hashlib
from datetime import datetime, timedelta

import requests
from flask import Flask, request, jsonify
from supabase import create_client

app = Flask(__name__)

# --------------------------------------------------
# ENV
# --------------------------------------------------
# Meta webhook verify token (support both names)
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN") or os.getenv("WHATSAPP_VERIFY_TOKEN", "")

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
def sha256_compare(signature_header: str, raw_body: bytes, secret: str) -> bool:
    """
    Verify Meta X-Hub-Signature-256.
    Header format: sha256=<hexdigest>
    """
    if not secret:
        # If you didn't set META_APP_SECRET, we cannot verify signatures safely.
        return False

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    their_sig = signature_header.split("=", 1)[1].strip()

    expected = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(their_sig, expected)


def verify_meta_signature(req) -> bool:
    signature = req.headers.get("X-Hub-Signature-256", "")
    return sha256_compare(signature, req.data, META_APP_SECRET)


def log_webhook(source: str, payload: dict):
    """
    Optional logging table: webhook_logs(source text, payload jsonb, created_at timestamptz default now()).
    If you didn't create it, this will silently ignore the error.
    """
    try:
        supabase.table("webhook_logs").insert({
            "source": source,
            "payload": payload
        }).execute()
    except Exception:
        pass


def send_whatsapp(to: str, text: str):
    if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
        print("Missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID")
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

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    try:
        data = r.json()
    except Exception:
        data = {"raw": r.text}

    # You can store send response if you want:
    # print("WA send:", r.status_code, data)
    return r.status_code, data


def dedup_seen(message_id: str) -> bool:
    """
    Returns True if already processed; False if it's new and recorded.
    Table: webhook_dedup(message_id text primary key, created_at timestamptz default now())
    """
    if not message_id:
        return False

    # Check
    try:
        exists = (
            supabase.table("webhook_dedup")
            .select("message_id")
            .eq("message_id", message_id)
            .limit(1)
            .execute()
        )
        if exists.data:
            return True
    except Exception as e:
        print("Dedup select error:", e)

    # Insert (best effort)
    try:
        supabase.table("webhook_dedup").insert({"message_id": message_id}).execute()
    except Exception as e:
        # If race condition causes duplicate insert, treat as already seen
        msg = str(e).lower()
        if "duplicate" in msg or "23505" in msg:
            return True
        print("Dedup insert error:", e)

    return False


def get_plan(plan: str):
    res = supabase.table("plans").select("*").eq("plan", plan).single().execute()
    return res.data


# --------------------------------------------------
# HEALTH / DEBUG
# --------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    return "OK", 200


@app.route("/debug", methods=["GET"])
def debug():
    # Safe browser endpoint (instead of /webhook)
    return jsonify({
        "status": "ok",
        "has_verify_token": bool(VERIFY_TOKEN),
        "has_whatsapp_token": bool(WHATSAPP_TOKEN),
        "phone_number_id_set": bool(PHONE_NUMBER_ID),
        "has_meta_app_secret": bool(META_APP_SECRET),
        "base_url": BASE_URL
    }), 200


# --------------------------------------------------
# WEBHOOK (META)
# --------------------------------------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # ---- VERIFY (Meta webhook verification)
    if request.method == "GET":
        mode = request.args.get("hub.mode", "")
        token = request.args.get("hub.verify_token", "")
        challenge = request.args.get("hub.challenge", "")

        if mode == "subscribe" and token and token == VERIFY_TOKEN:
            return challenge, 200

        # Browser visits will land here (no params) -> expected 403
        return "Forbidden", 403

    # ---- SECURITY: Verify Meta signature
    # IMPORTANT: Meta sends X-Hub-Signature-256 for real webhooks.
    # If META_APP_SECRET missing, we block for safety.
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    data = request.get_json(force=True, silent=True) or {}
    log_webhook("meta_webhook", data)

    try:
        entry = (data.get("entry") or [{}])[0]
        changes = (entry.get("changes") or [{}])[0]
        value = changes.get("value") or {}

        # 1) Handle inbound messages
        messages = value.get("messages") or []
        if messages:
            msg = messages[0]
            sender = msg.get("from", "")
            msg_id = msg.get("id", "")  # WhatsApp message id

            if dedup_seen(msg_id):
                return jsonify({"status": "duplicate"}), 200

            text = (msg.get("text") or {}).get("body", "").strip()
            text_up = text.upper()

            # Ensure user exists
            try:
                supabase.table("wa_users").upsert({"wa_phone": sender}).execute()
            except Exception as e:
                print("wa_users upsert error:", e)

            # HELP MENU
            if text_up in ["HELP", "MENU", "START"]:
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

            # SUBSCRIBE
            if text_up in ["BASIC", "STANDARD", "PREMIUM"]:
                plan = text_up.lower()
                plan_row = get_plan(plan)

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

            send_whatsapp(sender, "Reply *HELP* to continue.")
            return jsonify({"status": "ok"}), 200

        # 2) Handle delivery receipts / statuses (optional but useful)
        statuses = value.get("statuses") or []
        if statuses:
            st = statuses[0]
            status_id = st.get("id", "")
            # You can log these to another table if you created it (wa_delivery)
            try:
                supabase.table("wa_delivery").insert({
                    "message_id": status_id,
                    "status": st.get("status"),
                    "recipient_id": st.get("recipient_id"),
                    "payload": st
                }).execute()
            except Exception:
                pass

            return jsonify({"status": "status_event"}), 200

        return jsonify({"status": "ignored"}), 200

    except Exception as e:
        print("Webhook error:", e)
        return jsonify({"status": "error", "message": str(e)}), 200


# --------------------------------------------------
# PAYSTACK INIT
# --------------------------------------------------
def init_paystack(reference: str, amount_kobo: int, phone: str) -> str:
    if not PAYSTACK_SECRET:
        raise RuntimeError("PAYSTACK_SECRET_KEY missing in environment")

    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET}",
        "Content-Type": "application/json"
    }
    payload = {
        "reference": reference,
        "amount": int(amount_kobo),
        "email": f"{phone}@naijatax.app",
        "callback_url": f"{BASE_URL}/paystack/callback"
    }
    r = requests.post(url, headers=headers, json=payload, timeout=20)
    data = r.json()

    if not data.get("status"):
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

    if not signature or not hmac.compare_digest(signature, computed):
        return "Invalid", 403

    event = request.get_json(force=True, silent=True) or {}
    log_webhook("paystack_webhook", event)

    try:
        if event.get("event") == "charge.success":
            ref = event["data"]["reference"]
            phone = event["data"]["customer"]["email"].split("@")[0]

            plan = (
                supabase.table("payments")
                .select("plan")
                .eq("reference", ref)
                .single()
                .execute()
                .data["plan"]
            )

            duration = (
                supabase.table("plans")
                .select("duration_days")
                .eq("plan", plan)
                .single()
                .execute()
                .data["duration_days"]
            )

            expires = datetime.utcnow() + timedelta(days=int(duration))

            supabase.table("user_subscriptions").upsert({
                "wa_phone": phone,
                "plan": plan,
                "status": "active",
                "expires_at": expires.isoformat(),
                "paystack_reference": ref,
                "last_event": "charge.success"
            }).execute()

            # Mark payment as success too (recommended)
            supabase.table("payments").update({
                "status": "success"
            }).eq("reference", ref).execute()

            send_whatsapp(phone, f"✅ *{plan.upper()}* activated!\nExpires: {expires.date()}")

    except Exception as e:
        print("Paystack webhook error:", e)

    return "OK", 200
