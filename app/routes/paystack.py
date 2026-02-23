# app/routes/paystack.py
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan
from app.services.paystack_service import (
    PaystackHTTPError,
    create_reference,
    initialize_transaction,
    verify_transaction,
    verify_webhook_signature,
)
from app.services.subscriptions_service import activate_subscription_now

# IMPORTANT: must be named "bp" (your app registers dotted:...:bp)
bp = Blueprint("paystack", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _get_json_body() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


def _account_exists(account_id: str) -> bool:
    try:
        res = (
            _sb()
            .table("accounts")
            .select("account_id")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        return bool(rows)
    except Exception:
        # If Supabase is down, fail safe (don’t take money)
        return False


def _extract_init_fields(body: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Accept BOTH formats:

    A) Preferred:
      { "email": "...", "account_id": "...", "plan_code": "monthly" }

    B) Legacy/test:
      { "email": "...", "metadata": { "account_id":"...", "plan_code":"monthly" } }
    """
    email = (body.get("email") or "").strip()

    account_id = (body.get("account_id") or "").strip()
    plan_code = (body.get("plan_code") or "").strip().lower()

    if (not account_id or not plan_code) and isinstance(body.get("metadata"), dict):
        md = body["metadata"] or {}
        account_id = account_id or (md.get("account_id") or "").strip()
        plan_code = plan_code or (md.get("plan_code") or "").strip().lower()

    return email, account_id, plan_code


@bp.get("/paystack/health")
def paystack_health():
    # quick check that route is registered
    return jsonify({"ok": True, "service": "paystack"}), 200


@bp.post("/paystack/init")
def paystack_init():
    """
    Start a Paystack payment for a subscription plan.

    Body (preferred):
    {
      "email": "user@email.com",
      "account_id": "<uuid>",
      "plan_code": "monthly|quarterly|yearly"
    }
    """
    body = _get_json_body()
    email, account_id, plan_code = _extract_init_fields(body)

    if not email or not account_id or not plan_code:
        return jsonify(
            {
                "ok": False,
                "error": "email_account_id_plan_code_required",
                "received_keys": sorted(list(body.keys())),
            }
        ), 400

    # CRITICAL: prevent paying for a non-existent account (this caused your FK crash)
    if not _account_exists(account_id):
        return jsonify(
            {
                "ok": False,
                "error": "account_not_found",
                "hint": "Login first and use the real account_id from /api/web/auth/me, or create the accounts row before payment.",
                "account_id": account_id,
            }
        ), 400

    plan = get_plan(plan_code)
    if not plan or not plan.get("active", True):
        return jsonify({"ok": False, "error": "invalid_plan"}), 400

    amount_naira = int(plan.get("price") or 0)
    if amount_naira <= 0:
        return jsonify({"ok": False, "error": "invalid_plan_price"}), 400

    reference = create_reference("NTG")
    metadata = {
        "account_id": account_id,
        "plan_code": plan_code,
        "purpose": "subscription",
        # keep any extra metadata user sent
        **(body.get("metadata") or {}),
    }

    try:
        init_data = initialize_transaction(
            email=email,
            amount_naira=amount_naira,
            reference=reference,
            metadata=metadata,
        )
        d = init_data.get("data") or {}

        # best-effort store
        try:
            _sb().table("paystack_transactions").insert(
                {
                    "reference": reference,
                    "account_id": account_id,
                    "plan_code": plan_code,
                    "amount": amount_naira,
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

    except PaystackHTTPError as e:
        return jsonify(
            {
                "ok": False,
                "error": "paystack_init_failed",
                "paystack_status_code": e.status_code,
                "paystack_message": e.message,
                "root_cause": e.raw,
            }
        ), 400

    except Exception as e:
        return jsonify({"ok": False, "error": "init_failed", "root_cause": str(e)}), 400


@bp.get("/paystack/verify/<reference>")
def paystack_verify(reference: str):
    """
    Verify a transaction and (if successful) activate subscription.
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

        # best-effort update transaction row
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
            return jsonify(
                {
                    "ok": False,
                    "error": "missing_metadata",
                    "hint": "Paystack tx metadata must include account_id and plan_code",
                    "metadata_keys": sorted(list(metadata.keys())) if isinstance(metadata, dict) else [],
                }
            ), 400

        # Prevent FK crash (your exact issue)
        if not _account_exists(account_id):
            return jsonify(
                {
                    "ok": False,
                    "error": "account_not_found",
                    "hint": "This payment is real, but the account row does not exist in accounts table. Create the accounts row or use the correct logged-in account_id.",
                    "account_id": account_id,
                }
            ), 400

        sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")

        return jsonify({"ok": True, "reference": reference, "subscription": sub}), 200

    except PaystackHTTPError as e:
        return jsonify(
            {
                "ok": False,
                "error": "paystack_verify_failed",
                "paystack_status_code": e.status_code,
                "paystack_message": e.message,
                "root_cause": e.raw,
            }
        ), 400
    except Exception as e:
        return jsonify({"ok": False, "error": "verify_failed", "root_cause": str(e)}), 400


@bp.post("/paystack/webhook")
def paystack_webhook():
    """
    Paystack webhook endpoint.
    Verifies signature, then (optionally) verifies transaction via Paystack API,
    then activates subscription.
    """
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not verify_webhook_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    evt = request.get_json(silent=True) or {}
    event_name = (evt.get("event") or "").strip()
    data = evt.get("data") or {}

    # We only act on successful charges
    if event_name != "charge.success":
        return jsonify({"ok": True, "ignored": True, "event": event_name}), 200

    reference = (data.get("reference") or "").strip()
    if not reference:
        return jsonify({"ok": False, "error": "missing_reference"}), 400

    # safest: verify reference with Paystack before activation
    try:
        verified = verify_transaction(reference)
        tx = (verified.get("data") or {})
        status = (tx.get("status") or "").lower()
        metadata = tx.get("metadata") or {}

        if status != "success":
            return jsonify({"ok": True, "ignored": True, "paystack_status": status}), 200

        account_id = (metadata.get("account_id") or "").strip()
        plan_code = (metadata.get("plan_code") or "").strip().lower()

        if not account_id or not plan_code:
            return jsonify({"ok": False, "error": "missing_metadata"}), 400

        if not _account_exists(account_id):
            return jsonify({"ok": False, "error": "account_not_found", "account_id": account_id}), 400

        sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")
        return jsonify({"ok": True, "reference": reference, "subscription": sub}), 200

    except Exception as e:
        return jsonify({"ok": False, "error": "webhook_failed", "root_cause": str(e)}), 400
