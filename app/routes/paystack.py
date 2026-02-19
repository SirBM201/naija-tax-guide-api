# app/routes/paystack.py
from __future__ import annotations

from typing import Any, Dict
from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan
from app.services.paystack_service import create_reference, initialize_transaction, verify_transaction
from app.services.subscriptions_service import activate_subscription_now

paystack_bp = Blueprint("paystack", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


@paystack_bp.post("/paystack/init")
def paystack_init():
    """
    Start a Paystack payment for a subscription plan.

    Body:
    {
      "account_id": "<uuid>",
      "plan_code": "monthly|quarterly|yearly",
      "email": "user@email.com"
    }
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or "").strip()
    plan_code = (body.get("plan_code") or "").strip().lower()
    email = (body.get("email") or "").strip()

    if not account_id or not plan_code or not email:
        return jsonify({"ok": False, "error": "account_id_plan_code_email_required"}), 400

    plan = get_plan(plan_code)
    if not plan or not plan.get("active", True):
        return jsonify({"ok": False, "error": "invalid_plan"}), 400

    amount = int(plan.get("price") or 0)
    if amount <= 0:
        return jsonify({"ok": False, "error": "invalid_plan_price"}), 400

    reference = create_reference("NTG")
    metadata = {"account_id": account_id, "plan_code": plan_code, "purpose": "subscription"}

    try:
        init_data = initialize_transaction(email=email, amount_naira=amount, reference=reference, metadata=metadata)
        d = init_data.get("data") or {}

        # store initiated transaction (best-effort)
        try:
            _sb().table("paystack_transactions").insert(
                {
                    "reference": reference,
                    "account_id": account_id,
                    "plan_code": plan_code,
                    "amount": amount,
                    "currency": d.get("currency") or "NGN",
                    "status": "initiated",
                    "authorization_url": d.get("authorization_url"),
                    "access_code": d.get("access_code"),
                    "raw": init_data,
                }
            ).execute()
        except Exception:
            pass

        return jsonify(
            {
                "ok": True,
                "authorization_url": d.get("authorization_url"),
                "access_code": d.get("access_code"),
                "reference": reference,
            }
        ), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@paystack_bp.get("/paystack/verify/<reference>")
def paystack_verify(reference: str):
    """
    Verify a transaction and (if successful) activate the subscription.
    """
    reference = (reference or "").strip()
    if not reference:
        return jsonify({"ok": False, "error": "missing_reference"}), 400

    try:
        data = verify_transaction(reference)
        tx = (data.get("data") or {})
        status = (tx.get("status") or "").lower()
        metadata = tx.get("metadata") or {}

        account_id = (metadata.get("account_id") or "").strip()
        plan_code = (metadata.get("plan_code") or "").strip().lower()

        # update transaction row (best-effort)
        try:
            _sb().table("paystack_transactions").update(
                {
                    "paystack_status": status,
                    "transaction_id": str(tx.get("id") or ""),
                    "paid_at": tx.get("paid_at"),
                    "raw": data,
                    "status": "success" if status == "success" else "failed",
                }
            ).eq("reference", reference).execute()
        except Exception:
            pass

        if status != "success":
            return jsonify({"ok": False, "error": "payment_not_successful", "paystack_status": status}), 400

        if not account_id or not plan_code:
            return jsonify({"ok": False, "error": "missing_metadata"}), 400

        sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")

        return jsonify({"ok": True, "reference": reference, "subscription": sub}), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
