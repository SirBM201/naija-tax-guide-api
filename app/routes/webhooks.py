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
    mac = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha512).hexdigest()
    return hmac.compare_digest(mac, signature or "")

@bp.post("/webhooks/paystack")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not _verify_paystack_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    body = request.get_json(silent=True) or {}
    event = (body.get("event") or "").strip()

    # Most important event for subscriptions:
    # - charge.success (payment received)
    if event == "charge.success":
        data = body.get("data") or {}
        reference = (data.get("reference") or "").strip()
        if not reference:
            return jsonify({"ok": False, "error": "missing_reference"}), 400

        out = handle_payment_success(provider="paystack", reference=reference, payload=body)
        return jsonify(out), (200 if out.get("ok") else 202)

    # ignore others safely for now
    return jsonify({"ok": True, "ignored": event}), 200
