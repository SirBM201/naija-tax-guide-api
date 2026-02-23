# app/routes/paystack.py
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan
from app.services.paystack_service import (
    create_reference,
    initialize_transaction,
    verify_transaction,
    verify_webhook_signature,
)
from app.services.subscriptions_service import activate_subscription_now

paystack_bp = Blueprint("paystack", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _err(code: str, http: int = 400, *, detail: Optional[str] = None, extra: Optional[Dict[str, Any]] = None):
    payload: Dict[str, Any] = {"ok": False, "error": code}
    if detail:
        payload["detail"] = detail
    if extra:
        payload.update(extra)
    return jsonify(payload), http


def _parse_init_body(body: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[int], str, Dict[str, Any]]:
    """
    Supports BOTH payload styles:

    Style A (your current working test):
    {
      "email": "...",
      "amount_kobo": 20000,
      "currency": "NGN",
      "metadata": {"account_id":"...", "plan_code":"monthly", ...}
    }

    Style B (legacy):
    {
      "account_id":"...",
      "plan_code":"monthly",
      "email":"..."
    }

    Returns:
      email, account_id, plan_code, amount_kobo, currency, metadata
    """
    email = (body.get("email") or "").strip()

    # metadata can be nested
    metadata = body.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    # account_id/plan_code may be top-level OR inside metadata
    account_id = (body.get("account_id") or metadata.get("account_id") or "").strip()
    plan_code = (body.get("plan_code") or metadata.get("plan_code") or "").strip().lower()

    currency = (body.get("currency") or "NGN").strip()

    amount_kobo = body.get("amount_kobo", None)
    if amount_kobo is None:
        # allow "amount" as alias for compatibility, but treat it as kobo if provided
        amount_kobo = body.get("amount", None)

    amount_kobo_int: Optional[int] = None
    if amount_kobo is not None:
        try:
            amount_kobo_int = int(amount_kobo)
        except Exception:
            amount_kobo_int = None

    # Ensure we always keep important fields inside metadata
    # (so verify/webhook can reliably find them later)
    metadata_out = dict(metadata)
    if account_id:
        metadata_out["account_id"] = account_id
    if plan_code:
        metadata_out["plan_code"] = plan_code
    metadata_out.setdefault("purpose", "subscription")

    return email or None, account_id or None, plan_code or None, amount_kobo_int, currency, metadata_out


@paystack_bp.post("/paystack/init")
def paystack_init():
    """
    Start a Paystack payment.

    Accepts either:
    - amount_kobo + metadata (recommended; matches your screenshot)
    - OR account_id + plan_code + email (server computes amount)
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}
    email, account_id, plan_code, amount_kobo, currency, metadata = _parse_init_body(body)

    if not email:
        return _err("email_required", 400)

    if not account_id:
        return _err("account_id_required", 400)

    if not plan_code:
        return _err("plan_code_required", 400)

    # If client did not pass amount_kobo, compute from plan table
    if amount_kobo is None:
        plan = get_plan(plan_code)
        if not plan or not plan.get("active", True):
            return _err("invalid_plan", 400)
        price_naira = int(plan.get("price") or 0)
        if price_naira <= 0:
            return _err("invalid_plan_price", 400)
        amount_kobo = price_naira * 100

    if amount_kobo <= 0:
        return _err("invalid_amount_kobo", 400)

    reference = create_reference("NTG")

    try:
        init_data = initialize_transaction(
            email=email,
            amount_kobo=amount_kobo,
            currency=currency,
            reference=reference,
            metadata=metadata,
        )
        d = init_data.get("data") or {}

        # store initiated transaction (best-effort)
        try:
            _sb().table("paystack_transactions").insert(
                {
                    "reference": reference,
                    "account_id": account_id,
                    "plan_code": plan_code,
                    "amount": int(amount_kobo // 100),  # store as naira if you want
                    "amount_kobo": int(amount_kobo),
                    "currency": d.get("currency") or currency or "NGN",
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
        # IMPORTANT: never return empty body on 400
        return _err("paystack_init_failed", 400, detail=str(e))


@paystack_bp.get("/paystack/verify/<reference>")
def paystack_verify(reference: str):
    """
    Verify a transaction and (if successful) activate the subscription.

    Your frontend should call this after Paystack redirects back,
    using the returned reference.
    """
    reference = (reference or "").strip()
    if not reference:
        return _err("missing_reference", 400)

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
            return _err("payment_not_successful", 400, extra={"paystack_status": status})

        if not account_id or not plan_code:
            return _err("missing_metadata", 400, extra={"metadata": metadata})

        sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")
        return jsonify({"ok": True, "reference": reference, "subscription": sub}), 200

    except Exception as e:
        return _err("paystack_verify_failed", 400, detail=str(e))


@paystack_bp.post("/paystack/webhook")
def paystack_webhook():
    """
    Paystack webhook endpoint.

    - Verifies x-paystack-signature against RAW body
    - For charge.success, activates subscription using metadata.account_id + metadata.plan_code
    """
    raw_body: bytes = request.get_data(cache=False, as_text=False) or b""
    sig = (request.headers.get("x-paystack-signature") or "").strip()

    if not verify_webhook_signature(raw_body, sig):
        return _err("invalid_signature", 401)

    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    event = (payload.get("event") or "").strip().lower()
    data = payload.get("data") or {}
    if not isinstance(data, dict):
        data = {}

    # We only act on successful charges
    if event != "charge.success":
        return jsonify({"ok": True, "ignored": True, "event": event}), 200

    reference = (data.get("reference") or "").strip()
    status = (data.get("status") or "").strip().lower()
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    account_id = (metadata.get("account_id") or "").strip()
    plan_code = (metadata.get("plan_code") or "").strip().lower()

    # best-effort log/update transaction
    try:
        if reference:
            _sb().table("paystack_transactions").update(
                {
                    "paystack_status": status or "success",
                    "transaction_id": str(data.get("id") or ""),
                    "paid_at": data.get("paid_at"),
                    "status": "success" if status == "success" else "received",
                    "raw": payload,
                }
            ).eq("reference", reference).execute()
    except Exception:
        pass

    if status != "success":
        return _err("webhook_payment_not_success", 400, extra={"paystack_status": status, "reference": reference})

    if not account_id or not plan_code:
        return _err("missing_metadata", 400, extra={"reference": reference, "metadata": metadata})

    # Activate subscription (idempotency should be handled inside activate_subscription_now)
    try:
        sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")
        return jsonify({"ok": True, "reference": reference, "subscription": sub}), 200
    except Exception as e:
        return _err("activate_subscription_failed", 400, detail=str(e), extra={"reference": reference})
