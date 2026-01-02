import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, abort, jsonify

# Optional but recommended for Supabase + outbound replies
from supabase import create_client, Client
import requests

app = Flask(__name__)

# -------------------------
# Env vars (set in Koyeb)
# -------------------------
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify")

META_APP_SECRET = os.getenv("META_APP_SECRET", "")  # Meta App Secret for signature check
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "")    # WhatsApp Cloud API token
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "")  # from WhatsApp > API Setup

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

SERVICE_NAME = os.getenv("SERVICE_NAME", "naija-tax-guide-api")


# -------------------------
# Supabase client
# -------------------------
supabase: Client | None = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# -------------------------
# Health / Root (Koyeb friendly)
# -------------------------
@app.get("/")
def root():
    return jsonify({"service": SERVICE_NAME, "status": "ok"}), 200

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


# -------------------------
# Security: verify Meta signature
# -------------------------
def verify_meta_signature(req) -> bool:
    """
    Meta sends: X-Hub-Signature-256: sha256=<hash>
    We compute HMAC-SHA256(secret, raw_body).
    """
    if not META_APP_SECRET:
        # OK for early testing, but set this in production
        return True

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    provided_hash = signature.split("=", 1)[1]
    raw_body = req.get_data()  # bytes

    expected_hash = hmac.new(
        META_APP_SECRET.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(provided_hash, expected_hash)


# -------------------------
# WhatsApp outbound send
# -------------------------
def send_whatsapp_text(to_phone: str, message: str) -> tuple[bool, str]:
    """
    Sends a WhatsApp text message via Cloud API.
    Requires WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID.
    """
    if not (WHATSAPP_TOKEN and PHONE_NUMBER_ID):
        return False, "Missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID"

    url = f"https://graph.facebook.com/v21.0/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"body": message},
    }

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=15)
        if r.status_code >= 200 and r.status_code < 300:
            return True, "sent"
        return False, f"send_failed {r.status_code}: {r.text}"
    except Exception as e:
        return False, f"send_exception: {e}"


# -------------------------
# Basic flow router (auto-reply)
# -------------------------
def build_menu_text() -> str:
    return (
        "Naija Hustle Tax Guide 🇳🇬\n"
        "Reply with a number:\n\n"
        "1) PAYE Calculator (estimate)\n"
        "2) VAT Guide\n"
        "3) Withholding Tax (WHT) Guide\n"
        "4) Small Business Tax Tips\n"
        "5) Talk to Admin\n\n"
        "Type: MENU anytime to see this again."
    )

def route_message(text: str) -> str:
    t = (text or "").strip().lower()

    if t in ("menu", "hi", "hello", "help", "start"):
        return build_menu_text()

    # Quick numeric menu
    if t == "1":
        return (
            "PAYE Calculator (Estimate)\n"
            "Send your details in this format:\n"
            "PAYE gross=250000 pension=0 nhf=0 nhis=0\n\n"
            "Example:\n"
            "PAYE gross=500000 pension=25000"
        )

    if t == "2":
        return (
            "VAT Guide\n"
            "- VAT is charged on eligible goods/services.\n"
            "- Standard VAT rate has historically been 7.5%, but reforms have been discussed.\n"
            "Reply: VAT DETAILS to learn when to charge VAT and how to file."
        )

    if t == "3":
        return (
            "Withholding Tax (WHT) Guide\n"
            "Reply: WHT RENT or WHT CONTRACT or WHT PROFESSIONAL\n"
            "…and I will show typical rates + examples."
        )

    if t == "4":
        return (
            "Small Business Tax Tips\n"
            "Reply: SME TIPS\n"
            "or ask a question like:\n"
            "'Do I need TIN?' / 'How do I file PAYE?'"
        )

    if t == "5":
        return (
            "Okay. Please type your question and include your state (optional).\n"
            "An admin will respond as soon as possible."
        )

    # PAYE parsing (simple, configurable later)
    if t.startswith("paye"):
        # Example: PAYE gross=500000 pension=25000
        return handle_paye_estimate(text)

    if t.startswith("vat details"):
        return (
            "VAT DETAILS\n"
            "1) If you sell taxable goods/services, you may need to charge VAT.\n"
            "2) Keep VAT invoices/receipts.\n"
            "3) File/Remit based on your registration status.\n\n"
            "Reply: VAT EXAMPLE for a worked example."
        )

    if t.startswith("vat example"):
        return (
            "VAT EXAMPLE\n"
            "If you sold ₦100,000 of a VATable service:\n"
            "VAT = rate × 100,000\n"
            "Total invoice = 100,000 + VAT\n\n"
            "Reply: VAT RATE to see the configured rate in this bot."
        )

    if t.startswith("wht"):
        return handle_wht_info(t)

    return (
        "I didn’t understand that.\n\n"
        "Type MENU to see options, or send:\n"
        "- PAYE gross=250000 pension=0\n"
        "- VAT DETAILS\n"
        "- WHT RENT"
    )


def handle_wht_info(t: str) -> str:
    if "rent" in t:
        return "WHT RENT: Share landlord/tenant type + amount, and I’ll guide the steps."
    if "contract" in t:
        return "WHT CONTRACT: Share contract type + amount, and I’ll guide the likely WHT treatment."
    if "professional" in t:
        return "WHT PROFESSIONAL: Tell me the service type (legal, consulting, etc.)."
    return "WHT: Reply with WHT RENT or WHT CONTRACT or WHT PROFESSIONAL."


def handle_paye_estimate(raw_text: str) -> str:
    """
    Minimal PAYE estimator scaffold.
    IMPORTANT: We'll move rates/bands into Supabase config so you can update without redeploy.
    """
    # Parse key=val pairs
    parts = raw_text.replace(",", " ").split()
    kv = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            kv[k.strip().lower()] = v.strip()

    def to_num(x):
        try:
            return float(x)
        except:
            return 0.0

    gross = to_num(kv.get("gross", "0"))
    pension = to_num(kv.get("pension", "0"))
    nhf = to_num(kv.get("nhf", "0"))
    nhis = to_num(kv.get("nhis", "0"))

    if gross <= 0:
        return "PAYE: Please send gross salary. Example: PAYE gross=250000 pension=0"

    # CRA (Consolidated Relief Allowance) commonly referenced as:
    # CRA = higher of (₦200,000 + 20% of gross) or (1% of gross + 20% of gross)
    # We'll keep it configurable later; for now use the common form.
    cra = max(200000 + 0.20 * gross, 0.01 * gross + 0.20 * gross)

    deductions = pension + nhf + nhis
    taxable = max(0.0, gross - cra - deductions)

    # Progressive bands (common Nigeria PIT bands often cited):
    # 7% first 300k, 11% next 300k, 15% next 500k, 19% next 500k, 21% next 1.6m, 24% above
    # We'll keep it as an estimate and later store in Supabase config.
    tax = progressive_tax_estimate(taxable)

    return (
        "PAYE Estimate (Guide Only)\n"
        f"Gross: ₦{gross:,.2f}\n"
        f"CRA (est.): ₦{cra:,.2f}\n"
        f"Deductions (pension+nhf+nhis): ₦{deductions:,.2f}\n"
        f"Taxable: ₦{taxable:,.2f}\n"
        f"Estimated Annual Tax: ₦{tax:,.2f}\n\n"
        "Reply: PAYE MONTHLY to convert to monthly, or MENU to go back."
    )

def progressive_tax_estimate(taxable: float) -> float:
    bands = [
        (300000, 0.07),
        (300000, 0.11),
        (500000, 0.15),
        (500000, 0.19),
        (1600000, 0.21),
        (float("inf"), 0.24),
    ]
    remaining = taxable
    total = 0.0
    for limit, rate in bands:
        chunk = min(remaining, limit)
        if chunk <= 0:
            break
        total += chunk * rate
        remaining -= chunk
    return total


# -------------------------
# Idempotency + logging helpers
# -------------------------
def already_processed(message_id: str) -> bool:
    if not (supabase and message_id):
        return False
    r = supabase.table("webhook_dedup").select("message_id").eq("message_id", message_id).limit(1).execute()
    return bool(r.data)

def mark_processed(message_id: str):
    if not (supabase and message_id):
        return
    supabase.table("webhook_dedup").insert({
        "message_id": message_id,
        "created_at": datetime.now(timezone.utc).isoformat()
    }).execute()

def log_event(event: dict):
    if not supabase:
        return
    supabase.table("webhook_events").insert({
        "received_at": datetime.now(timezone.utc).isoformat(),
        "payload": event
    }).execute()


# -------------------------
# Webhook endpoint
# -------------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # --- Verification (Meta GET)
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            return challenge, 200
        abort(403)

    # --- Incoming webhook (Meta POST)
    if not verify_meta_signature(request):
        abort(403)

    data = request.get_json(silent=True) or {}
    log_event(data)

    # WhatsApp message payload shape: entry[0].changes[0].value.messages[0]
    try:
        entry = data.get("entry", [])
        if not entry:
            return "EVENT_RECEIVED", 200

        changes = entry[0].get("changes", [])
        if not changes:
            return "EVENT_RECEIVED", 200

        value = changes[0].get("value", {})
        messages = value.get("messages", [])

        # Status updates may arrive without messages
        if not messages:
            return "EVENT_RECEIVED", 200

        msg = messages[0]
        message_id = msg.get("id", "")
        from_phone = msg.get("from", "")
        text = (msg.get("text") or {}).get("body", "")

        if message_id and already_processed(message_id):
            return "EVENT_RECEIVED", 200

        reply = route_message(text)

        # send reply (only if token configured)
        if from_phone and reply:
            ok, info = send_whatsapp_text(from_phone, reply)
            # Optional: store reply status
            if supabase:
                supabase.table("outbound_messages").insert({
                    "message_id": message_id or None,
                    "to_phone": from_phone,
                    "inbound_text": text,
                    "reply_text": reply,
                    "sent_ok": ok,
                    "send_info": info,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }).execute()

        if message_id:
            mark_processed(message_id)

    except Exception as e:
        # Do not break webhook; Meta expects fast 200
        print(f"Webhook processing error: {e}")

    return "EVENT_RECEIVED", 200


# -------------------------
# Koyeb entrypoint
# -------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
