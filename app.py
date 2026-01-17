import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, request, jsonify
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
APP_ENV = os.getenv("APP_ENV", "production")
APP_PORT = int(os.getenv("APP_PORT", os.getenv("PORT", "8000")))

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

# Optional: used to build URLs you send back to users
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "").rstrip("/")
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

# Limits (optional)
FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "5"))
PAID_DAILY_LIMIT = int(os.getenv("PAID_DAILY_LIMIT", "50"))
DEFAULT_PLAN_DAYS = int(os.getenv("DEFAULT_PLAN_DAYS", "30"))

# ------------------------------------------------------------
# Clients
# ------------------------------------------------------------
supabase = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def json_response(payload: Dict[str, Any], code: int = 200):
    return jsonify(payload), code

def _safe_str(x: Any) -> str:
    return "" if x is None else str(x)

def normalize_phone(raw: str) -> str:
    # Expect WhatsApp number from webhook like "234xxxxxxxxxx"
    # Keep digits only.
    return "".join([c for c in _safe_str(raw) if c.isdigit()])

def get_subscription(wa_phone: str) -> Dict[str, Any]:
    if not supabase:
        return {"plan": "free", "status": "inactive", "expires_at": None}

    try:
        res = supabase.table("user_subscriptions").select("*").eq("wa_phone", wa_phone).maybe_single().execute()
        row = res.data or None
        if not row:
            return {"plan": "free", "status": "inactive", "expires_at": None}
        return {
            "plan": row.get("plan") or "free",
            "status": row.get("status") or "inactive",
            "expires_at": row.get("expires_at")
        }
    except Exception as e:
        logging.exception("get_subscription error: %s", e)
        return {"plan": "free", "status": "inactive", "expires_at": None}

def activate_user_subscription(wa_phone: str, plan: str) -> None:
    # Basic activation; you can map monthly/quarterly/yearly to durations if you want.
    days = DEFAULT_PLAN_DAYS
    p = (plan or "").lower().strip()
    if p == "monthly":
        days = 30
    elif p == "quarterly":
        days = 90
    elif p == "yearly":
        days = 365

    expires_at = iso(now_utc() + timedelta(days=days))
    if not supabase:
        return

    supabase.table("user_subscriptions").upsert(
        {
            "wa_phone": wa_phone,
            "plan": p,
            "status": "active",
            "expires_at": expires_at,
            "updated_at": iso(now_utc()),
        },
        on_conflict="wa_phone",
    ).execute()

def send_whatsapp_text(to_phone: str, text: str) -> Tuple[bool, str]:
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        return False, "WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID not set"

    url = f"https://graph.facebook.com/v20.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"preview_url": False, "body": text}
    }

    try:
        r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=20)
        if r.status_code >= 200 and r.status_code < 300:
            return True, "sent"
        return False, f"send failed {r.status_code}: {r.text}"
    except Exception as e:
        logging.exception("send_whatsapp_text error: %s", e)
        return False, str(e)

def parse_whatsapp_inbound(payload: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """
    Returns (from_phone, message_text) or None if not a user text message.
    """
    try:
        entry = payload.get("entry", [])
        if not entry:
            return None

        changes = entry[0].get("changes", [])
        if not changes:
            return None

        value = changes[0].get("value", {})
        messages = value.get("messages", [])
        if not messages:
            return None

        msg = messages[0]
        from_phone = normalize_phone(msg.get("from"))
        msg_type = msg.get("type")

        if msg_type == "text":
            text = msg.get("text", {}).get("body", "")
            return from_phone, text.strip()

        # You can extend for interactive/button/list later
        return None
    except Exception as e:
        logging.exception("parse_whatsapp_inbound error: %s", e)
        return None

def handle_command(wa_phone: str, text: str) -> Optional[str]:
    """
    Returns a reply string if the message is a command; otherwise None.
    """
    t = (text or "").strip()
    up = t.upper()

    if up in ("HELP", "HI", "HELLO", "START"):
        return (
            "Welcome to Naija Tax Guide.\n\n"
            "Commands:\n"
            "• PLANS – see subscription plans\n"
            "• STATUS – check your subscription\n"
            "• SUBSCRIBE MONTHLY | QUARTERLY | YEARLY\n"
            "• Ask any tax question anytime.\n"
        )

    if up == "PLANS":
        return (
            "Subscription Plans:\n"
            "• MONTHLY: ₦3,000\n"
            "• QUARTERLY: ₦8,000\n"
            "• YEARLY: ₦30,000\n\n"
            "To subscribe: send\n"
            "SUBSCRIBE MONTHLY\n"
            "or SUBSCRIBE QUARTERLY\n"
            "or SUBSCRIBE YEARLY"
        )

    if up == "STATUS":
        sub = get_subscription(wa_phone)
        plan = sub.get("plan", "free")
        status = sub.get("status", "inactive")
        exp = sub.get("expires_at")
        return f"Your status:\n• Plan: {plan}\n• Status: {status}\n• Expires: {exp or 'N/A'}"

    if up.startswith("SUBSCRIBE"):
        # Expected: SUBSCRIBE MONTHLY / QUARTERLY / YEARLY
        parts = t.split()
        if len(parts) < 2:
            return "Please choose a plan:\nSUBSCRIBE MONTHLY\nSUBSCRIBE QUARTERLY\nSUBSCRIBE YEARLY"

        plan = parts[1].lower().strip()
        if plan not in ("monthly", "quarterly", "yearly"):
            return "Invalid plan. Use:\nSUBSCRIBE MONTHLY\nSUBSCRIBE QUARTERLY\nSUBSCRIBE YEARLY"

        # Here you have two options:
        # 1) If Paystack is already live: reply with a payment link (recommended).
        # 2) For now, just confirm you captured intent, and you can trigger /paystack/initialize from frontend/admin.
        #
        # If you already have a frontend purchase page, use it:
        if FRONTEND_BASE_URL:
            return f"To complete your {plan} subscription, open:\n{FRONTEND_BASE_URL}/subscribe?plan={plan}&phone={wa_phone}"

        return (
            f"Subscription request received: {plan}.\n"
            "Next step: complete payment (Paystack). If you have not enabled the payment page yet, ask admin."
        )

    return None

# ------------------------------------------------------------
# Core API
# ------------------------------------------------------------
@app.get("/health")
def health():
    return json_response({"ok": True})

@app.get("/routes")
def routes():
    rules = []
    for r in app.url_map.iter_rules():
        if r.endpoint == "static":
            continue
        rules.append({"endpoint": r.endpoint, "methods": sorted(list(r.methods)), "rule": str(r)})
    return jsonify(rules)

@app.post("/ask")
def ask():
    """
    This is the same endpoint you already tested.
    Keep it stable. WhatsApp will call into this logic from /whatsapp/webhook (POST).
    """
    data = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(data.get("wa_phone", ""))
    question = (data.get("question") or "").strip()

    if not wa_phone or not question:
        return json_response({"ok": False, "error": "wa_phone and question are required"}, 400)

    # Cache hook (your system can implement real caching; keep response stable for now)
    # Example: return cached answer if exists; otherwise call AI.
    # For now, keep your placeholder behavior:
    return json_response({
        "ok": True,
        "cached": False,
        "answer": {"meta": "", "text": "Cache miss. AI call will be connected here next."}
    })

# ------------------------------------------------------------
# Paystack (kept as-is, since you already have it working)
# ------------------------------------------------------------
@app.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    secret = PAYSTACK_WEBHOOK_SECRET or PAYSTACK_SECRET_KEY
    if not secret:
        return "PAYSTACK_WEBHOOK_SECRET/PAYSTACK_SECRET_KEY not set", 500

    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    # Handle charge.success -> activate subscription if metadata has wa_phone + plan
    try:
        if event.get("event") == "charge.success":
            data = event.get("data", {}) or {}
            meta = data.get("metadata", {}) or {}
            wa_phone = normalize_phone(meta.get("wa_phone"))
            plan = (meta.get("plan") or "").lower().strip()

            if wa_phone and plan:
                activate_user_subscription(wa_phone, plan)
                logging.info("Activated subscription for %s plan=%s", wa_phone, plan)

        return "ok", 200
    except Exception as e:
        logging.exception("paystack webhook error: %s", e)
        return "ok", 200

# ------------------------------------------------------------
# WhatsApp Cloud API Webhook
# ------------------------------------------------------------
@app.get("/whatsapp/webhook")
def whatsapp_webhook_verify():
    """
    Meta verifies your callback URL by calling GET with:
    hub.mode=subscribe
    hub.verify_token=...
    hub.challenge=...
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token and WHATSAPP_VERIFY_TOKEN and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200

    return "forbidden", 403

@app.post("/whatsapp/webhook")
def whatsapp_webhook_inbound():
    """
    Inbound WhatsApp messages come here (POST).
    We:
      1) parse the text
      2) run command menu (HELP/PLANS/STATUS/SUBSCRIBE)
      3) otherwise call /ask logic (same code path) and send reply back to user
    """
    payload = request.get_json(silent=True) or {}

    parsed = parse_whatsapp_inbound(payload)
    if not parsed:
        # Always return 200 to Meta quickly; they will retry if you error.
        return "ok", 200

    wa_phone, text = parsed
    logging.info("WA inbound from=%s text=%s", wa_phone, text)

    # 1) Commands
    cmd_reply = handle_command(wa_phone, text)
    if cmd_reply:
        ok, msg = send_whatsapp_text(wa_phone, cmd_reply)
        if not ok:
            logging.warning("WA send failed: %s", msg)
        return "ok", 200

    # 2) Normal question -> reuse /ask logic
    #    (Call the function directly to avoid internal HTTP)
    try:
        # Build same payload you used in PowerShell
        req_payload = {"wa_phone": wa_phone, "question": text}

        # Inline call to logic: (same behavior as /ask endpoint)
        # Replace this block later with your REAL cache + AI logic.
        result = {
            "ok": True,
            "cached": False,
            "answer": {"meta": "", "text": "Cache miss. AI call will be connected here next."}
        }

        answer_text = result.get("answer", {}).get("text", "") or "OK"
        send_whatsapp_text(wa_phone, answer_text)
    except Exception as e:
        logging.exception("WA inbound handling failed: %s", e)
        send_whatsapp_text(wa_phone, "Sorry — an error occurred. Please try again.")

    return "ok", 200

# ------------------------------------------------------------
# Entrypoint (local)
# ------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=APP_PORT)
