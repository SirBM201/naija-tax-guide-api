# paystack/webhook.py
import hmac
import hashlib
import logging
from typing import Any, Dict, Optional

from flask import request

# IMPORTANT:
# This module assumes these helpers/objects exist in your project and are imported here.
# If your project keeps them in different modules, adjust the import paths accordingly.

from app import (
    PAYSTACK_SECRET_KEY,
    CURRENCY,
    PLAN_PRICES,
    now_utc,
    iso,
    normalize_wa_phone,
    upsert_payment_row,
    activate_user_subscription,
    record_paystack_event,
)

log = logging.getLogger(__name__)


def _verify_signature(raw: bytes, signature: str) -> bool:
    if not PAYSTACK_SECRET_KEY or not signature:
        return False
    expected = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def register_paystack_webhook(app) -> None:
    """
    Registers:
      POST /webhooks/paystack
    """

    @app.post("/webhooks/paystack")
    def paystack_webhook_handler():
        raw = request.get_data() or b""
        sig = (request.headers.get("x-paystack-signature") or "").strip()

        if not PAYSTACK_SECRET_KEY:
            return "PAYSTACK_SECRET_KEY not set", 500

        if not _verify_signature(raw, sig):
            return "invalid signature", 401

        event = request.get_json(force=True, silent=True) or {}
        event_type = str(event.get("event") or "").strip()
        data = event.get("data") or {}

        reference = str(data.get("reference") or "").strip()
        tx_id = data.get("id")

        # Stable idempotency key (Paystack retries)
        if tx_id:
            event_id = f"{event_type}:{tx_id}"
        elif reference:
            event_id = f"{event_type}:{reference}"
        else:
            event_id = hashlib.sha256(raw).hexdigest()

        inserted = record_paystack_event(
            event_id=event_id,
            event_type=event_type,
            reference=reference or None,
            payload=event,
        )
        if not inserted:
            return "OK", 200  # duplicate retry

        status = str(data.get("status") or "").lower()
        amount_kobo = data.get("amount")
        currency = str(data.get("currency") or CURRENCY)

        metadata = data.get("metadata") or {}
        wa_phone = normalize_wa_phone(str(metadata.get("wa_phone") or ""))
        plan = str(metadata.get("plan") or "").lower()
        purpose = str(metadata.get("purpose") or "")

        # Always upsert payments when we have reference
        if reference:
            try:
                upsert_payment_row(
                    reference=reference,
                    wa_phone=wa_phone or None,
                    plan=plan or None,
                    amount_kobo=int(amount_kobo) if amount_kobo is not None else None,
                    currency=currency,
                    status="success" if event_type == "charge.success" else (status or event_type),
                    provider="paystack",
                    paid_at=iso(now_utc()) if event_type == "charge.success" else None,
                    raw_event=event,
                )
            except Exception:
                log.exception("payments upsert failed (webhook)")

        # Activate only on charge.success for subscriptions
        if event_type == "charge.success":
            if purpose == "subscription" and wa_phone and plan in PLAN_PRICES:
                try:
                    activate_user_subscription(wa_phone, plan)
                except Exception:
                    log.exception("activate_user_subscription failed (webhook)")

        return "OK", 200
