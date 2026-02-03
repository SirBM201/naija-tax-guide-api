# app/routes/webhooks.py
import os
import hmac
import hashlib
from flask import Blueprint, request, jsonify

from ..services.subscriptions_service import handle_payment_success

bp = Blueprint("webhooks", __name__)

# -----------------------------
# Paystack
# -----------------------------
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", "").strip()

def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    if not PAYSTACK_WEBHOOK_SECRET:
        return False
    digest = hmac.new(
        PAYSTACK_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(digest, signature or "")

@bp.post("/webhooks/paystack")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if PAYSTACK_WEBHOOK_SECRET and not _verify_paystack_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    event = request.json or {}
    event_id = event.get("id") or event.get("event_id")
    event_type = (event.get("event") or "").lower()
    data = event.get("data") or {}

    if event_type not in ("charge.success",):
        return jsonify({"ok": True, "ignored": True, "event": event_type})

    meta = data.get("metadata") or {}
    account_id = (meta.get("account_id") or "").strip()
    plan_code = (meta.get("plan_code") or "").strip()

    reference = data.get("reference")
    amount_kobo = data.get("amount")
    currency = data.get("currency", "NGN")

    out = handle_payment_success({
        "event_id": event_id,
        "provider": "paystack",
        "reference": reference,
        "account_id": account_id,
        "plan_code": plan_code,
        "amount_kobo": amount_kobo,
        "currency": currency,
        "raw": event,
    })

    return jsonify(out), (200 if out.get("ok") else 400)

# -----------------------------
# Meta (WhatsApp / Messenger / Instagram)
# -----------------------------
META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "").strip()

@bp.get("/webhooks/meta")
def meta_verify():
    """
    Meta webhook verification endpoint.
    Configure this URL in:
    - WhatsApp Cloud API webhooks
    - Facebook Messenger webhooks
    - Instagram webhooks
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and META_VERIFY_TOKEN and token == META_VERIFY_TOKEN:
        return challenge, 200
    return "forbidden", 403

@bp.post("/webhooks/meta")
def meta_events():
    """
    Receives Meta webhook events.
    For now: just acknowledge. Later we will route to:
    - WA inbound handler
    - Messenger inbound handler
    - Instagram DM inbound handler
    """
    payload = request.get_json(silent=True) or {}

    # TODO next: route by payload structure.
    # We'll implement in the inbound routes step.
    return jsonify({"ok": True}), 200
