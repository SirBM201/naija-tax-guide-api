# app/routes/webhooks.py
import os
import hmac
import hashlib
from flask import Blueprint, request, jsonify

from ..services.subscriptions_service import handle_payment_success

bp = Blueprint("webhooks", __name__)

PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", "").strip()

def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    if not PAYSTACK_WEBHOOK_SECRET:
        return False
    digest = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, signature or "")

@bp.post("/webhooks/paystack")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    # In production, enforce signature
    if PAYSTACK_WEBHOOK_SECRET and not _verify_paystack_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    event = request.json or {}
    event_id = event.get("id") or event.get("event_id")  # Paystack includes an id
    event_type = (event.get("event") or "").lower()
    data = event.get("data") or {}

    # We only care about successful charge events
    # Common: "charge.success"
    if event_type not in ("charge.success",):
        return jsonify({"ok": True, "ignored": True, "event": event_type})

    # You must decide how to map Paystack metadata -> account_id/plan_code.
    # Best practice: set metadata when initializing payment.
    meta = data.get("metadata") or {}
    account_id = (meta.get("account_id") or "").strip()
    plan_code = (meta.get("plan_code") or "").strip()

    # Fallbacks (if you stored differently)
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
        # optional: "upgrade_mode": "at_expiry"
    })

    code = 200 if out.get("ok") else 400
    return jsonify(out), code
