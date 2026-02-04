# app/routes/paystack_webhook.py
import os
import hmac
import hashlib
import json
import logging
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase  # your existing client factory

bp = Blueprint("paystack_webhook", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()


def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack: X-Paystack-Signature = HMAC SHA512(raw_body, secret_key)
    """
    if not PAYSTACK_SECRET_KEY or not signature:
        return False
    digest = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, signature)


def _mark_event_processed(event_id: str, event_type: str, reference: str | None, payload: dict) -> bool:
    """
    Idempotency:
    - Insert into paystack_events with UNIQUE(event_id)
    - If already exists, skip processing
    Returns True if inserted newly, False if already exists.
    """
    sb = supabase()
    try:
        res = (
            sb.table("paystack_events")
            .insert(
                {
                    "event_id": event_id,
                    "event_type": event_type,
                    "reference": reference,
                    "payload": payload,
                }
            )
            .execute()
        )
        # Insert success
        return True
    except Exception as e:
        # If duplicate unique key, treat as already processed
        msg = str(e).lower()
        if "duplicate" in msg or "unique" in msg or "23505" in msg:
            return False
        raise


def _activate_subscription_from_reference(reference: str) -> None:
    """
    Your backend likely already has logic to:
    - verify transaction by reference
    - map plan_code
    - set subscriptions.active, expires_at, etc
    Here we call your existing RPC if you have it; otherwise do a safe update pattern.

    ✅ Best practice:
    Use ONE server-side function that verifies Paystack transaction and updates DB.
    """

    sb = supabase()

    # OPTION 1 (recommended): if you already have an RPC that finalizes by reference:
    # sb.rpc("finalize_paystack_reference", {"p_reference": reference}).execute()
    #
    # If you DON'T have RPC, keep it simple:
    # - call your existing /api/paystack/verify endpoint from inside backend services (not shown)
    # - or implement verify here.

    # For now, we assume you already have an RPC:
    sb.rpc("finalize_paystack_reference", {"p_reference": reference}).execute()


@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data()  # bytes
    sig = request.headers.get("x-paystack-signature", "")

    if not _verify_paystack_signature(raw, sig):
        # Always return 200 to reduce retries noise, but log it
        logging.warning("Paystack webhook signature invalid")
        return jsonify({"ok": True}), 200

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        logging.exception("Paystack webhook: invalid JSON")
        return jsonify({"ok": True}), 200

    event_type = payload.get("event", "")
    data = payload.get("data", {}) or {}

    event_id = payload.get("id") or data.get("id")  # paystack sometimes puts id in data
    reference = data.get("reference")

    if not event_id:
        logging.warning("Paystack webhook missing event_id")
        return jsonify({"ok": True}), 200

    # Idempotency gate
    inserted = _mark_event_processed(
        event_id=str(event_id),
        event_type=str(event_type),
        reference=str(reference) if reference else None,
        payload=payload,
    )
    if not inserted:
        # Already processed
        return jsonify({"ok": True}), 200

    # Process only relevant events
    # The most important: charge.success (payment completed)
    if event_type == "charge.success" and reference:
        try:
            _activate_subscription_from_reference(reference)
        except Exception:
            logging.exception("Paystack webhook: failed to activate subscription for reference=%s", reference)
            # Still 200 so Paystack won't hammer you; you can replay manually using saved payload
            return jsonify({"ok": True}), 200

    return jsonify({"ok": True}), 200
