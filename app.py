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
# Use one name consistently. In Meta dashboard you typed "naija-tax-guide-verify"
# So set this env var to that exact string.
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN") or os.getenv("VERIFY_TOKEN")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
META_APP_SECRET = os.getenv("META_APP_SECRET", "")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY")
BASE_URL = (os.getenv("BASE_URL") or "").rstrip("/")  # e.g. https://xxxx.koyeb.app

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY")
if not WHATSAPP_TOKEN or not PHONE_NUMBER_ID:
    raise RuntimeError("Missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID")
if not PAYSTACK_SECRET:
    raise RuntimeError("Missing PAYSTACK_SECRET_KEY")
if not VERIFY_TOKEN:
    raise RuntimeError("Missing WHATSAPP_VERIFY_TOKEN (or VERIFY_TOKEN)")
if not BASE_URL:
    raise RuntimeError("Missing BASE_URL (your Koyeb public URL)")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --------------------------------------------------
# UTILITIES
# --------------------------------------------------
def verify_meta_signature(req) -> bool:
    """
    Meta sends X-Hub-Signature-256: sha256=...
    If META_APP_SECRET is not set, we allow (dev convenience).
    """
    if not META_APP_SECRET:
        return True

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    body = req.get_data()  # raw bytes
    expected = hmac.new(
        META_APP_SECRET.encode("utf-8"),
        body,
        hashlib.sha256
    ).hexdigest()

    provided = signature.split("=", 1)[1].strip()
    return hmac.compare_digest(provided, expected)


def send_whatsapp(to: str, text: str) -> bool:
    url = f"https://graph.facebook.com/v19.0/{PHONE_NUMBER_ID}/messages"
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
        # Helpful logs when messages don't deliver
        if r.status_code >= 400:
            print("send_whatsapp failed:", r.status_code, r.text)
            return False
        return True
    except Exception as e:
        print("send_whatsapp exception:", e)
        return False


def safe_single(exec_result):
    # supabase-py returns .data on execute()
    return exec_result.data if hasattr(exec_result, "data") else None


def get_message_id(payload: dict) -> str:
    """
    DEDUP should use the WhatsApp message id, NOT entry.id (entry.id is NOT unique per message).
    """
    try:
        return payload["entry"][0]["changes"][0]["value"]["messages"][0]["id"]
    except Exception:
        return ""


def get_text_from_payload(payload: dict) -> str:
    """
    Handle normal text + interactive replies.
    """
    msg = payload["entry"][0]["changes"][0]["value"]["messages"][0]

    mtype = msg.get("type", "")
    if mtype == "text":
        return (msg.get("text", {}).get("body") or "").strip()

    # Buttons / lists etc.
    if mtype == "interactive":
        inter = msg.get("interactive", {})
        itype = inter.get("type")
        if itype == "button_reply":
            return (inter.get("button_reply", {}).get("title") or "").strip()
        if itype == "list_reply":
            return (inter.get("list_reply", {}).get("title") or "").strip()

    # Fallback
    return ""


def get_sender(payload: dict) -> str:
    try:
        return payload["entry"][0]["changes"][0]["value"]["messages"][0]["from"]
    except Exception:
        return ""


def log_event(kind: str, payload: dict):
    """
    Optional logging table. If you don't have it, comment it out.
    """
    try:
        supabase.table("webhook_logs").insert({
            "kind": kind,
            "payload": payload,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
    except Exception:
        pass


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
    # ---- VERIFY (Meta subscription handshake)
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        # If browser hits /webhook with no params, don't scare you with "Forbidden"
        if not mode:
            return "OK", 200

        if mode == "subscribe" and token == VERIFY_TOKEN:
            return challenge, 200

        return "Verification failed", 403

    # ---- SECURITY (POST must be verified)
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    data = request.get_json(silent=True) or {}
    log_event("meta_webhook", data)

    # ---- Ignore delivery/status events (no "messages")
    try:
        value = data["entry"][0]["changes"][0]["value"]
        if "messages" not in value:
            # e.g. statuses only
            return "EVENT_RECEIVED", 200
    except Exception:
        return "EVENT_RECEIVED", 200

    # ---- DEDUP by WhatsApp message id
    msg_id = get_message_id(data)
    if msg_id:
        try:
            exists = supabase.table("webhook_dedup").select("id").eq("id", msg_id).execute()
            if safe_single(exists):
                return jsonify({"status": "duplicate"}), 200
            supabase.table("webhook_dedup").insert({"id": msg_id}).execute()
        except Exception as e:
            # If dedup table missing, don't break webhook delivery
            print("dedup error:", e)

    sender = get_sender(data)
    if not sender:
        return "EVENT_RECEIVED", 200

    try:
        raw_text = get_text_from_payload(data)
        text = (raw_text or "").strip().upper()

        # Ensure user row exists
        try:
            supabase.table("wa_users").upsert({"wa_phone": sender}).execute()
        except Exception:
            pass

        # ---- HELP MENU
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

        # ---- SUBSCRIBE
        if text in ["BASIC", "STANDARD", "PREMIUM"]:
            plan = text.lower()

            plan_res = supabase.table("plans").select("*").eq("plan", plan).single().execute()
            plan_row = safe_single(plan_res)
            if not plan_row:
                send_whatsapp(sender, "⚠️ Plan not found. Reply HELP.")
                return jsonify({"status": "plan_missing"}), 200

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

            send_whatsapp(
                sender,
                f"💳 Pay to activate *{plan.upper()}*:\n{pay_url}\n\nAfter payment, you will be activated automatically."
            )
            return jsonify({"status": "payment_link"}), 200

        send_whatsapp(sender, "Reply HELP to continue.")
        return jsonify({"status": "fallback"}), 200

    except Exception as e:
        print("Webhook error:", e)
        # Always 200 so Meta doesn’t disable your webhook
        return "EVENT_RECEIVED", 200


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
        "amount": int(amount_kobo),  # kobo
        "email": f"{phone}@naijatax.app",
        # Callback is optional; webhook is what activates.
        "callback_url": f"{BASE_URL}/paystack/callback"
    }

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    if r.status_code >= 400:
        print("paystack init failed:", r.status_code, r.text)
        raise RuntimeError("Paystack initialize failed")

    j = r.json()
    return j["data"]["authorization_url"]


# --------------------------------------------------
# PAYSTACK CALLBACK (optional user landing page)
# --------------------------------------------------
@app.route("/paystack/callback", methods=["GET"])
def paystack_callback():
    """
    Paystack will redirect here after payment.
    Activation still happens via /paystack/webhook.
    """
    ref = request.args.get("reference") or request.args.get("trxref") or ""
    return f"Payment received. If successful, your subscription will activate automatically. Ref: {ref}", 200


# --------------------------------------------------
# PAYSTACK WEBHOOK
# --------------------------------------------------
@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    signature = request.headers.get("x-paystack-signature", "")
    if not signature:
        return "Missing signature", 403

    computed = hmac.new(
        PAYSTACK_SECRET.encode("utf-8"),
        request.get_data(),
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(signature, computed):
        return "Invalid", 403

    event = request.get_json(silent=True) or {}
    log_event("paystack_webhook", event)

    try:
        if event.get("event") != "charge.success":
            return "OK", 200

        data = event.get("data", {})
        ref = data.get("reference", "")
        cust = data.get("customer", {}) or {}
        email = cust.get("email", "")
        phone = email.split("@")[0] if "@" in email else ""

        if not ref or not phone:
            return "OK", 200

        # Mark payment success
        try:
            supabase.table("payments").update({
                "status": "success",
                "paid_at": datetime.utcnow().isoformat()
            }).eq("reference", ref).execute()
        except Exception:
            pass

        pay_row_res = supabase.table("payments").select("plan").eq("reference", ref).single().execute()
        pay_row = safe_single(pay_row_res)
        if not pay_row:
            return "OK", 200

        plan = pay_row["plan"]

        duration_res = supabase.table("plans").select("duration_days").eq("plan", plan).single().execute()
        duration_row = safe_single(duration_res)
        duration = int(duration_row["duration_days"]) if duration_row else 30

        expires = datetime.utcnow() + timedelta(days=duration)

        # Ensure status column exists in user_subscriptions table
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

    except Exception as e:
        print("paystack webhook error:", e)
        return "OK", 200


# --------------------------------------------------
# OPTIONAL: delivery receipts endpoint (Meta already hits /webhook)
# You do NOT need a second endpoint; statuses come to /webhook.
# --------------------------------------------------

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
