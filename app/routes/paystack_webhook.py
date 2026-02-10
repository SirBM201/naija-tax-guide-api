# app/routes/paystack_webhook.py
from __future__ import annotations

import os
import hmac
import hashlib
import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.services.paystack_service import verify_transaction
from app.services.subscriptions_service import handle_payment_success

bp = Blueprint("paystack_webhook", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verify_sig(raw_body: bytes, sig: str) -> bool:
    if not PAYSTACK_SECRET_KEY or not sig:
        return False
    digest = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, sig)


@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data()
    sig = request.headers.get("x-paystack-signature", "")

    if not _verify_sig(raw, sig):
        logging.warning("Paystack webhook: invalid signature")
        return jsonify({"ok": True}), 200  # always 200 to avoid retries storm

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        logging.exception("Paystack webhook: invalid JSON")
        return jsonify({"ok": True}), 200

    event_type = (payload.get("event") or "").strip()
    data = payload.get("data") or {}
    reference = (data.get("reference") or "").strip()
    if event_type != "charge.success" or not reference:
        return jsonify({"ok": True}), 200

    sb = supabase()

    # quick idempotency guard: already success in payments table
    existing = None
    try:
        p = (
            sb.table("payments")
            .select("status, amount_kobo, currency, plan, plan_code, wa_phone, account_id, email")
            .eq("reference", reference)
            .limit(1)
            .execute()
        )
        existing = (p.data or [None])[0]
        if existing and (existing.get("status") or "").lower() == "success":
            return jsonify({"ok": True}), 200
    except Exception:
        existing = None

    # real proof: verify with Paystack
    try:
        verified = verify_transaction(reference)
    except Exception:
        logging.exception("Paystack webhook: verify failed ref=%s", reference)
        return jsonify({"ok": True}), 200

    vdata = (verified.get("data") or {})
    if (vdata.get("status") or "").lower() != "success":
        return jsonify({"ok": True}), 200

    amount_paid = int(vdata.get("amount") or 0)
    currency = (vdata.get("currency") or "NGN").upper()

    md = vdata.get("metadata") or {}
    if not isinstance(md, dict):
        md = {}

    account_id = (md.get("account_id") or "").strip() or (existing.get("account_id") if existing else "")
    plan_code = (md.get("plan_code") or "").strip().lower() or (existing.get("plan_code") if existing else "") or (existing.get("plan") if existing else "")
    upgrade_mode = (md.get("upgrade_mode") or "now").strip().lower()
    wa_phone = (md.get("wa_phone") or "").strip() or (existing.get("wa_phone") if existing else "")
    email = (md.get("email") or "").strip() or (existing.get("email") if existing else "") or ((vdata.get("customer") or {}).get("email") or "")

    # optional mismatch guard vs stored pending row
    if existing:
        try:
            expected_amt = int(existing.get("amount_kobo") or 0)
            expected_cur = (existing.get("currency") or "NGN").upper()
            if expected_amt and amount_paid != expected_amt:
                logging.warning("Paystack webhook: amount mismatch ref=%s paid=%s expected=%s", reference, amount_paid, expected_amt)
                return jsonify({"ok": True}), 200
            if expected_cur and currency != expected_cur:
                logging.warning("Paystack webhook: currency mismatch ref=%s paid=%s expected=%s", reference, currency, expected_cur)
                return jsonify({"ok": True}), 200
        except Exception:
            pass

    # mirror paystack_payments (best-effort)
    try:
        sb.table("paystack_payments").upsert(
            {
                "reference": reference,
                "wa_phone": wa_phone or None,
                "email": email or None,
                "plan": plan_code or None,
                "amount_kobo": amount_paid,
                "currency": currency,
                "status": "success",
                "gateway_response": vdata.get("gateway_response"),
                "raw": verified,
                "updated_at": _utc_now_iso(),
            },
            on_conflict="reference",
        ).execute()
    except Exception:
        pass

    # essentials required for activation
    if not account_id or not plan_code or not wa_phone:
        logging.warning(
            "Paystack webhook: missing essentials ref=%s account_id=%s plan_code=%s wa_phone=%s",
            reference, bool(account_id), bool(plan_code), bool(wa_phone)
        )
        return jsonify({"ok": True}), 200

    # cheap safety: validate plan exists
    try:
        plan = sb.table("plans").select("plan_code").eq("plan_code", plan_code).limit(1).execute()
        if not (plan.data or []):
            logging.warning("Paystack webhook: plan not found plan_code=%s ref=%s", plan_code, reference)
            return jsonify({"ok": True}), 200
    except Exception:
        pass

    # central handler
    try:
        handle_payment_success(
            {
                "provider": "paystack",
                "reference": reference,
                "account_id": account_id,
                "plan_code": plan_code,
                "upgrade_mode": upgrade_mode,
                "amount_kobo": amount_paid,
                "currency": currency,
                "wa_phone": wa_phone,
                "email": email or None,
                "raw": verified,
            }
        )
    except Exception:
        logging.exception("Paystack webhook: handle_payment_success failed ref=%s", reference)
        return jsonify({"ok": True}), 200

    return jsonify({"ok": True}), 200
