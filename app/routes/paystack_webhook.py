# app/routes/paystack_webhook.py
import os
import hmac
import hashlib
import json
import logging
from typing import Any, Dict, Optional

from flask import Blueprint, request, jsonify

# Uses your existing Supabase client factory (service role key)
from app.core.supabase_client import supabase

bp = Blueprint("paystack_webhook", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

# If you want Postman/manual testing without real Paystack signature,
# set this env var to "true" (ONLY in dev):
# PAYSTACK_WEBHOOK_ALLOW_UNSIGNED=true
ALLOW_UNSIGNED = os.getenv("PAYSTACK_WEBHOOK_ALLOW_UNSIGNED", "false").lower() == "true"


def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack: x-paystack-signature = HMAC SHA512(raw_body, secret_key)
    """
    if not PAYSTACK_SECRET_KEY:
        return False
    if not signature:
        return False

    digest = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512,
    ).hexdigest()

    return hmac.compare_digest(digest, signature)


def _safe_json_loads(raw: bytes) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _mark_event_processed(
    event_id: str,
    event_type: str,
    reference: Optional[str],
    payload: Dict[str, Any],
) -> bool:
    """
    Idempotency gate:
    - Insert into paystack_events with UNIQUE(event_id)
    - If already exists, skip processing
    Returns True if inserted newly, False if already exists.

    NOTE: You must create paystack_events table (SQL below).
    """
    sb = supabase()
    try:
        sb.table("paystack_events").insert(
            {
                "event_id": event_id,
                "event_type": event_type,
                "reference": reference,
                "payload": payload,
            }
        ).execute()
        return True
    except Exception as e:
        msg = str(e).lower()

        # If table missing, DON'T crash webhook; just log and proceed without idempotency
        if "relation" in msg and "does not exist" in msg and "paystack_events" in msg:
            logging.warning("paystack_events table not found; idempotency disabled until table is created")
            return True

        # Duplicate unique key -> already processed
        if "duplicate" in msg or "unique" in msg or "23505" in msg:
            return False

        raise


def _finalize_subscription(reference: str) -> None:
    """
    Best practice: keep all subscription update logic in ONE database RPC or server function.

    Your code currently assumes you have:
      RPC: finalize_paystack_reference(p_reference text)

    If you don't have it yet, tell me and I will generate:
    - the RPC SQL
    - the verify-transaction logic
    - the subscription update logic
    """
    sb = supabase()
    sb.rpc("finalize_paystack_reference", {"p_reference": reference}).execute()


@bp.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "").strip()

    # 1) Verify signature (production)
    if not _verify_paystack_signature(raw, sig):
        # Allow unsigned ONLY in dev when you explicitly enable it
        if not ALLOW_UNSIGNED:
            logging.warning("Paystack webhook: invalid/missing signature")
            # Return 200 so Paystack doesn't hammer retries; log is enough
            return jsonify({"ok": True}), 200
        logging.warning("Paystack webhook: unsigned request accepted (DEV MODE)")

    # 2) Parse JSON
    payload = _safe_json_loads(raw)
    if not payload:
        logging.exception("Paystack webhook: invalid JSON body")
        return jsonify({"ok": True}), 200

    event_type = str(payload.get("event") or "")
    data = payload.get("data") or {}

    # Paystack often has event id inside payload["data"]["id"]
    event_id = payload.get("id") or data.get("id")
    reference = data.get("reference")

    if not event_id:
        logging.warning("Paystack webhook: missing event_id")
        return jsonify({"ok": True}), 200

    # 3) Idempotency gate
    inserted = _mark_event_processed(
        event_id=str(event_id),
        event_type=event_type,
        reference=str(reference) if reference else None,
        payload=payload,
    )
    if not inserted:
        # Already processed this event
        return jsonify({"ok": True}), 200

    # 4) Process relevant events
    # Most important: charge.success
    if event_type == "charge.success" and reference:
        try:
            _finalize_subscription(str(reference))
        except Exception:
            logging.exception("Paystack webhook: finalize failed for reference=%s", reference)
            # Still return 200; payload is saved so you can replay later
            return jsonify({"ok": True}), 200

    return jsonify({"ok": True}), 200
