# app/routes/paystack_webhook.py
from __future__ import annotations

import os
import hmac
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta

from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.services.paystack_service import verify_transaction

bp = Blueprint("paystack_webhook", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()


def _verify_sig(raw_body: bytes, sig: str) -> bool:
    if not PAYSTACK_SECRET_KEY or not sig:
        return False
    digest = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, sig)


@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data()  # bytes
    sig = request.headers.get("x-paystack-signature", "")

    # Paystack will POST. GET in browser will be 405 and that's NORMAL.
    if not _verify_sig(raw, sig):
        logging.warning("Paystack webhook: invalid signature")
        return jsonify({"ok": True}), 200  # return 200 to avoid spam retries

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        logging.exception("Paystack webhook: invalid JSON")
        return jsonify({"ok": True}), 200

    event_type = payload.get("event", "")
    data = payload.get("data", {}) or {}
    reference = data.get("reference")

    if event_type != "charge.success" or not reference:
        return jsonify({"ok": True}), 200

    sb = supabase()

    # 1) verify with Paystack (this is the REAL proof)
    try:
        verified = verify_transaction(reference)
    except Exception:
        logging.exception("Paystack webhook: verify failed ref=%s", reference)
        return jsonify({"ok": True}), 200

    vdata = (verified.get("data") or {})
    if vdata.get("status") != "success":
        logging.warning("Paystack verify says not success ref=%s status=%s", reference, vdata.get("status"))
        return jsonify({"ok": True}), 200

    amount_paid = int(vdata.get("amount") or 0)
    currency = (vdata.get("currency") or "NGN").upper()

    # 2) load the pending tx we created in init
    tx_res = sb.table("paystack_tx").select("*").eq("reference", reference).limit(1).execute()
    tx = (tx_res.data or [None])[0]
    if not tx:
        logging.warning("Paystack webhook: no pending tx found for ref=%s", reference)
        return jsonify({"ok": True}), 200

    # Idempotency: if already success, stop
    if (tx.get("status") or "") == "success":
        return jsonify({"ok": True}), 200

    expected_amount = int(tx["amount_kobo"])
    if amount_paid != expected_amount or currency != (tx.get("currency") or "NGN").upper():
        logging.warning(
            "Paystack webhook: amount mismatch ref=%s paid=%s expected=%s currency=%s",
            reference, amount_paid, expected_amount, currency
        )
        # mark failed to prevent looping confusion
        sb.table("paystack_tx").update({"status": "failed"}).eq("reference", reference).execute()
        return jsonify({"ok": True}), 200

    account_id = tx["account_id"]
    plan_code = tx["plan_code"]

    # 3) lookup plan duration
    plan_res = sb.table("plans").select("duration_days").eq("plan_code", plan_code).limit(1).execute()
    plan = (plan_res.data or [None])[0]
    if not plan:
        logging.warning("Paystack webhook: plan not found plan_code=%s", plan_code)
        sb.table("paystack_tx").update({"status": "failed"}).eq("reference", reference).execute()
        return jsonify({"ok": True}), 200

    duration_days = int(plan["duration_days"])

    # 4) write subscription (upsert style)
    now = datetime.now(timezone.utc)
    end_at = now + timedelta(days=duration_days)

    # if you use subscriptions.user_id column to store account_id, keep it consistent:
    # your subscriptions table shows user_id uuid — we’ll store account_id there.
    sb.table("subscriptions").upsert(
        {
            "user_id": account_id,
            "plan": plan_code,
            "status": "active",
            "start_at": now.isoformat(),
            "end_at": end_at.isoformat(),
            "paystack_ref": reference,
            "amount_kobo": amount_paid,
            "currency": currency,
            "updated_at": now.isoformat(),
        },
        on_conflict="user_id",
    ).execute()

    # 5) mark tx success
    sb.table("paystack_tx").update(
        {"status": "success", "updated_at": now.isoformat()}
    ).eq("reference", reference).execute()

    return jsonify({"ok": True}), 200
