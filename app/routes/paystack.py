# app/routes/paystack.py
from __future__ import annotations

from typing import Any, Dict, Optional
from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan
from app.services.paystack_service import (
    create_reference,
    initialize_transaction,
    verify_transaction,
    health as paystack_health,
)
from app.services.subscriptions_service import activate_subscription_now

paystack_bp = Blueprint("paystack", __name__)

# Optional alias so older imports like app.routes.paystack:bp still work
bp = paystack_bp


def _sb():
    return supabase() if callable(supabase) else supabase


def _json_error(status: int, code: str, *, message: str = "", root_cause: Any = None, extra: Dict[str, Any] | None = None):
    payload: Dict[str, Any] = {"ok": False, "error": code}
    if message:
        payload["message"] = message
    if root_cause is not None:
        payload["root_cause"] = root_cause
    if extra:
        payload["extra"] = extra
    return jsonify(payload), status


def _ensure_account_exists(account_id: str, email: str) -> Optional[Dict[str, Any]]:
    """
    Fixes FK failures by ensuring accounts row exists before writing user_subscriptions.
    We keep it minimal (provider=web, provider_user_id=email) so it won't break existing model.
    """
    if not account_id:
        return None

    # 1) check exists
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
        if rows:
            return rows[0]
    except Exception:
        pass

    # 2) create stub (best-effort)
    try:
        ins = (
            _sb()
            .table("accounts")
            .insert(
                {
                    "account_id": account_id,
                    "provider": "web",
                    "provider_user_id": (email or "").strip() or account_id,
                    "display_name": (email or "").strip(),
                }
            )
            .execute()
        )
        rows = (ins.data or []) if hasattr(ins, "data") else []
        return rows[0] if rows else {"account_id": account_id}
    except Exception as e:
        # If it fails (RLS etc), we return None and let caller expose root cause
        return None


@paystack_bp.get("/paystack/health")
def health():
    return jsonify(paystack_health()), 200


@paystack_bp.post("/paystack/init")
def paystack_init():
    """
    Start a Paystack payment.

    Supports TWO modes:

    A) Plan mode (recommended)
    {
      "account_id": "<uuid>",
      "plan_code": "monthly|quarterly|yearly",
      "email": "user@email.com"
    }

    B) Amount mode (for raw testing)
    {
      "account_id": "<uuid>",
      "email": "user@email.com",
      "amount_kobo": 20000,
      "currency": "NGN",
      "metadata": {...}
    }
    """
    body: Dict[str, Any] = request.get_json(silent=True) or {}

    account_id = (body.get("account_id") or "").strip()
    plan_code = (body.get("plan_code") or "").strip().lower()
    email = (body.get("email") or "").strip()

    if not account_id or not email:
        return _json_error(400, "account_id_email_required")

    # Build metadata
    metadata = body.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    # Always ensure required metadata fields exist
    metadata.setdefault("account_id", account_id)
    if plan_code:
        metadata.setdefault("plan_code", plan_code)
        metadata.setdefault("purpose", "subscription")

    # Amount resolution
    amount_naira: Optional[int] = None
    amount_kobo: Optional[int] = None

    if plan_code:
        plan = get_plan(plan_code)
        if not plan or not plan.get("active", True):
            return _json_error(400, "invalid_plan")
        amount_naira = int(plan.get("price") or 0)
        if amount_naira <= 0:
            return _json_error(400, "invalid_plan_price")
    else:
        # raw test mode
        if body.get("amount_kobo") is not None:
            amount_kobo = int(body.get("amount_kobo") or 0)
        elif body.get("amount_naira") is not None:
            amount_naira = int(body.get("amount_naira") or 0)
        elif body.get("amount") is not None:
            # tolerate "amount" meaning kobo (common in earlier tests)
            amount_kobo = int(body.get("amount") or 0)
        else:
            return _json_error(400, "plan_code_or_amount_required")

    reference = create_reference("NTG")

    try:
        init_data = initialize_transaction(
            email=email,
            amount_naira=amount_naira,
            amount_kobo=amount_kobo,
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
                    "plan_code": plan_code or None,
                    "amount": amount_naira or (amount_kobo or 0) / 100,
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
        return _json_error(400, "paystack_init_failed", message=str(e))


@paystack_bp.get("/paystack/verify/<reference>")
def paystack_verify(reference: str):
    """
    Verify a transaction and (if successful) activate the subscription.

    This endpoint now:
    - updates paystack_transactions (best-effort)
    - ensures accounts row exists (to avoid FK failures)
    - then upserts user_subscriptions
    """
    reference = (reference or "").strip()
    if not reference:
        return _json_error(400, "missing_reference")

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
            return _json_error(400, "payment_not_successful", extra={"paystack_status": status})

        if not account_id or not plan_code:
            return _json_error(400, "missing_metadata", extra={"metadata": metadata})

        # ✅ Critical FK fix: ensure accounts row exists
        ensured = _ensure_account_exists(account_id=account_id, email=str(tx.get("customer", {}).get("email") or ""))
        if not ensured:
            return _json_error(
                400,
                "account_missing_and_cannot_create",
                message="Account row missing and could not be created (RLS or schema mismatch).",
                extra={"account_id": account_id},
            )

        # Activate subscription
        try:
            sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")
            return jsonify({"ok": True, "reference": reference, "subscription": sub}), 200
        except Exception as e:
            # Root-cause exposer
            return _json_error(
                400,
                "db_upsert_failed",
                message=str(e),
                root_cause={
                    "table": "user_subscriptions",
                    "where": "activate_subscription_now",
                    "hint": "Upsert failed. Common causes: FK missing accounts row, RLS denies, or wrong service role key.",
                    "meta": {"account_id": account_id, "plan_code": plan_code},
                },
            )

    except Exception as e:
        return _json_error(400, "paystack_verify_failed", message=str(e))
