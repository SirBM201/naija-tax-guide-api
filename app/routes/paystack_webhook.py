# app/routes/paystack_webhook.py
from __future__ import annotations

from typing import Any, Dict
from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.paystack_service import verify_webhook_signature
from app.services.subscriptions_service import activate_subscription_now

bp = Blueprint("paystack_webhook", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


@bp.post("/paystack/webhook")
def paystack_webhook():
    """
    Paystack webhook endpoint.
    Paystack sends header: x-paystack-signature
    """
    raw = request.get_data() or b""
    sig = (request.headers.get("x-paystack-signature") or "").strip()

    if not verify_webhook_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    event = (payload.get("event") or "").strip()
    data = payload.get("data") or {}
    reference = (data.get("reference") or "").strip()
    status = (data.get("status") or "").lower()
    metadata = data.get("metadata") or {}

    # Store webhook raw (best-effort)
    try:
        _sb().table("paystack_transactions").update(
            {"paystack_status": status, "raw": payload, "status": "success" if status == "success" else "failed"}
        ).eq("reference", reference).execute()
    except Exception:
        pass

    # We only auto-activate on successful charge
    if event in ("charge.success", "subscription.create", "invoice.payment_succeeded") and status == "success":
        account_id = (metadata.get("account_id") or "").strip()
        plan_code = (metadata.get("plan_code") or "").strip().lower()

        if account_id and plan_code:
            try:
                activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")
            except Exception:
                # do not fail webhook response
                pass

    # Always return 200 quickly to Paystack
    return jsonify({"ok": True}), 200
