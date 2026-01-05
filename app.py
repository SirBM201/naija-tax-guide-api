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
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")  # must match Meta webhook verify token
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")  # REQUIRED (this is what you send messages with)
META_APP_SECRET = os.getenv("META_APP_SECRET", "")  # REQUIRED for signature verification

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")  # service role for server-side writes

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY", "")
BASE_URL = os.getenv("BASE_URL", "").rstrip("/")  # e.g. https://developed-lizabeth-bmsconcept-e65bfd1d.koyeb.app

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def utcnow_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def sb_safe_insert(table: str, row: dict):
    """Never let Supabase logging crash the webhook."""
    try:
        supabase.table(table).insert(row).execute()
    except Exception:
        pass


def verify_meta_signature(req) -> bool:
    """
    Meta sends header: X-Hub-Signature-256: sha256=<hash>
    Hash = HMAC_SHA256(app_secret, raw_request_body)
    """
    if not META_APP_SECRET:
        return False

    sig = req.headers.get("X-Hub-Signature-256", "")
    if not sig.startswith("sha256="):
        return False

    expected = hmac.new(
        META_APP_SECRET.encode("utf-8"),
        req.data,
        hashlib.sha256
    ).hexdigest()

    received = sig.split("=", 1)[1]
    return hmac.compare_digest(received, expected)


def send_whatsapp(to: str, text: str):
    """Send a simple text message via WhatsApp Cloud API."""
    if not PHONE_NUMBER_ID or not WHATSAPP_TOKEN:
        return

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
        sb_safe_insert("webhook_logs", {
            "source": "send_whatsapp",
            "created_at": utcnow_iso(),
            "payload": {"to": to, "status_code": r.status_code, "resp": safe_json(r)}
        })
    except Exception as e:
        sb_safe_insert("webhook_logs", {
            "source": "send_whatsapp_error",
            "created_at": utcnow_iso(),
            "payload": {"to": to, "err": str(e)}
        })


def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {"text": resp.text[:500]}


def dedup_seen(message_id: str) -> bool:
    """
    Your table is: webhook_dedup(message_id text primary key, created_at timestamptz default now())
    If message_id already exists -> duplicate.
    """
    if not message_id:
        return False

    try:
        exists = supabase.table("webhook_dedup").select("message_id").eq("message_id", message_id).execute()
        if exists.data:
            return True
        supabase.table("webhook_dedup").insert({"message_id": message_id}).execute()
        return False
    except Exception as e:
        # If dedup fails, do NOT crash webhook
        sb_safe_insert("webhook_logs", {
            "source": "dedup_error",
            "created_at": utcnow_iso(),
            "payload": {"message_id": message_id, "err": str(e)}
        })
        return False


def get_plan(plan: str):
    """plans table expected: plan (basic/standard/premium), amount_kobo, duration_days"""
    try:
        return supabase.table("plans").select("*").eq("plan", plan).single().execute().data
    except Exception:
        return None


def get_active_subscription(wa_phone: str):
    """
    user_subscriptions expected: wa_phone, status, expires_at, plan
    """
    try:
        row = (
            supabase.table("user_subscriptions")
            .select("status, expires_at, plan")
            .eq("wa_phone", wa_phone)
            .single()
            .execute()
            .data
        )
        if not row:
            return None

        status = (row.get("status") or "").lower()
        expires_at = row.get("expires_at")

        # If expires_at exists, check if it is in the past
        if expires_at:
            try:
                exp = datetime.fromisoformat(expires_at.replace("Z", ""))
                if exp < datetime.utcnow():
                    return None
            except Exception:
                pass

        if status == "active":
            return row
        return None
    except Exception:
        return None


def init_paystack(reference: str, amount_kobo: int, phone: str) -> str:
    """
    Paystack initialization.
    Note: Paystack will append reference and status to callback redirect itself.
    """
    if not PAYSTACK_SECRET:
        return ""

    url = "https://api.paystack.co/transaction/initialize"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET}",
        "Content-Type": "application/json",
    }
    payload = {
        "reference": reference,
        "amount": amount_kobo,
        "email": f"{phone}@naijatax.app",
        "callback_url": f"{BASE_URL}/paystack/callback" if BASE_URL else None,
        "metadata": {"wa_phone": phone},
    }

    r = requests.post(url, headers=headers, json=payload, timeout=20)
    data = r.json()
    if not data.get("status"):
        sb_safe_insert("webhook_logs", {
            "source": "paystack_init_failed",
            "created_at": utcnow_iso(),
            "payload": data
        })
        return ""

    return data["data"]["authorization_url"]


def verify_paystack_signature(req) -> bool:
    """
    Paystack header: x-paystack-signature = HMAC_SHA512(secret_key, raw_body)
    """
    signature = req.headers.get("x-paystack-signature", "")
    if not signature or not PAYSTACK_SECRET:
        return False

    computed = hmac.new(
        PAYSTACK_SECRET.encode("utf-8"),
        req.data,
        hashlib.sha512
    ).hexdigest()

    return hmac.compare_digest(signature, computed)


# --------------------------------------------------
# ROUTES
# --------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    return "OK", 200


@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # ---------------------------
    # VERIFY (GET) - Meta Challenge
    # ---------------------------
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
            return challenge, 200

        # Browser opening /webhook will show Forbidden (normal)
        return "Forbidden", 403

    # ---------------------------
    # SECURITY (POST) - Signature
    # ---------------------------
    if not verify_meta_signature(request):
        return "Invalid signature", 403

    # ---------------------------
    # PARSE
    # ---------------------------
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"status": "bad_json"}), 200

    # Optional logging (create webhook_logs table if you want)
    sb_safe_insert("webhook_logs", {
        "source": "meta_webhook_in",
        "created_at": utcnow_iso(),
        "payload": data
    })

    # Meta structure:
    # entry[] -> changes[] -> value -> messages[] OR statuses[]
    try:
        entries = data.get("entry", [])
        for entry in entries:
            changes = entry.get("changes", [])
            for change in changes:
                value = change.get("value", {})

                # 1) DELIVERY RECEIPTS / STATUSES
                statuses = value.get("statuses", [])
                for st in statuses:
                    sb_safe_insert("wa_delivery", {
                        "created_at": utcnow_iso(),
                        "message_id": st.get("id"),
                        "status": st.get("status"),
                        "recipient_id": st.get("recipient_id"),
                        "raw": st
                    })

                # 2) INCOMING MESSAGES
                messages = value.get("messages", [])
                for msg in messages:
                    message_id = msg.get("id")  # THIS is the correct dedup key
                    if message_id and dedup_seen(message_id):
                        continue

                    sender = msg.get("from", "")
                    text = (msg.get("text", {}) or {}).get("body", "") or ""
                    text_up = text.strip().upper()

                    # Save/Upsert user
                    try:
                        supabase.table("wa_users").upsert({"wa_phone": sender}).execute()
                    except Exception:
                        pass

                    # ---------------------------
                    # MAIN BOT LOGIC
                    # ---------------------------
                    if text_up in ["HELP", "MENU", "START"]:
                        send_whatsapp(
                            sender,
                            (
                                "*Naija Tax Guide*\n\n"
                                "1) BASIC – ₦3,000 (30 days)\n"
                                "2) STANDARD – ₦8,000 (90 days)\n"
                                "3) PREMIUM – ₦30,000 (1 year)\n\n"
                                "Reply with: BASIC or STANDARD or PREMIUM"
                            )
                        )
                        continue

                    # If active subscription, allow access (placeholder)
                    active = get_active_subscription(sender)
                    if active:
                        # You can replace this with your real tax assistant logic
                        send_whatsapp(sender, "✅ Subscription active. Ask your tax question now.")
                        continue

                    # Subscription purchase flow
                    if text_up in ["BASIC", "STANDARD", "PREMIUM"]:
                        plan = text_up.lower()
                        plan_row = get_plan(plan)

                        if not plan_row:
                            send_whatsapp(sender, "❌ Plan not found. Reply HELP to see plans.")
                            continue

                        reference = f"NTG-{sender}-{int(datetime.utcnow().timestamp())}"

                        # record pending payment
                        try:
                            supabase.table("payments").insert({
                                "wa_phone": sender,
                                "provider": "paystack",
                                "reference": reference,
                                "plan": plan,
                                "amount_kobo": plan_row["amount_kobo"],
                                "currency": "NGN",
                                "status": "pending",
                                "created_at": utcnow_iso(),
                            }).execute()
                        except Exception as e:
                            send_whatsapp(sender, f"❌ Payment record error. Try again. ({str(e)[:40]})")
                            continue

                        pay_url = init_paystack(reference, int(plan_row["amount_kobo"]), sender)
                        if not pay_url:
                            send_whatsapp(sender, "❌ Paystack init failed. Reply HELP and try again.")
                            continue

                        send_whatsapp(sender, f"💳 Pay to activate *{plan.upper()}*:\n{pay_url}")
                        continue

                    # Default response for non-subscribed users
                    send_whatsapp(sender, "Reply HELP to see plans and activate your subscription.")

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        # Never crash Meta webhook; always 200
        sb_safe_insert("webhook_logs", {
            "source": "meta_webhook_error",
            "created_at": utcnow_iso(),
            "payload": {"err": str(e)}
        })
        return jsonify({"status": "error"}), 200


@app.route("/paystack/callback", methods=["GET"])
def paystack_callback():
    # This is only for Paystack redirect after payment (webhook is what activates subscription)
    return "Payment received. You can return to WhatsApp.", 200


@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    if not verify_paystack_signature(request):
        return "Invalid", 403

    event = request.get_json(force=True)
    sb_safe_insert("webhook_logs", {
        "source": "paystack_in",
        "created_at": utcnow_iso(),
        "payload": event
    })

    try:
        if event.get("event") != "charge.success":
            return "OK", 200

        data = event.get("data", {})
        ref = data.get("reference")
        customer = data.get("customer", {}) or {}
        email = customer.get("email", "")
        phone = email.split("@")[0] if "@" in email else ""

        if not ref or not phone:
            return "OK", 200

        # Mark payment success
        try:
            supabase.table("payments").update({
                "status": "success",
                "paid_at": utcnow_iso(),
                "raw_event": event
            }).eq("reference", ref).execute()
        except Exception:
            pass

        # Determine plan & duration
        pay_row = supabase.table("payments").select("plan").eq("reference", ref).single().execute().data
        plan = pay_row.get("plan") if pay_row else None
        if not plan:
            return "OK", 200

        plan_row = supabase.table("plans").select("duration_days").eq("plan", plan).single().execute().data
        duration = int(plan_row.get("duration_days", 30)) if plan_row else 30

        expires = datetime.utcnow() + timedelta(days=duration)

        # Activate subscription
        supabase.table("user_subscriptions").upsert({
            "wa_phone": phone,
            "plan": plan,
            "status": "active",
            "expires_at": expires.replace(microsecond=0).isoformat() + "Z",
            "paystack_reference": ref,
            "last_event": "charge.success",
            "updated_at": utcnow_iso(),
        }).execute()

        send_whatsapp(phone, f"✅ *{plan.upper()}* activated!\nExpires: {expires.date()}")

        return "OK", 200

    except Exception as e:
        sb_safe_insert("webhook_logs", {
            "source": "paystack_error",
            "created_at": utcnow_iso(),
            "payload": {"err": str(e)}
        })
        return "OK", 200
