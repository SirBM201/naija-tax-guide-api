# app/routes/paystack.py
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan
from app.services.paystack_service import (
    PaystackError,
    create_reference,
    initialize_transaction,
    verify_transaction,
    verify_webhook_signature,
)
from app.services.subscriptions_service import activate_subscription_now

# IMPORTANT:
# Export name MUST be `bp` if your app/__init__.py imports "app.routes.paystack:bp"
paystack_bp = Blueprint("paystack", __name__)
bp = paystack_bp  # <-- critical alias to fix 404 due to blueprint not registering


def _sb():
    return supabase() if callable(supabase) else supabase


def _json_error(code: int, error: str, **extra: Any):
    payload = {"ok": False, "error": error}
    payload.update(extra)
    return jsonify(payload), code


def _extract_init_fields(body: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[int], Optional[str], Dict[str, Any]]:
    """
    Supports BOTH client styles:

    A) Preferred server-side pricing:
      { "account_id": "...", "plan_code": "monthly", "email": "..." }

    B) Your PowerShell style:
      { "email": "...", "amount_kobo": 20000, "currency": "NGN",
        "metadata": {"account_id":"...","plan_code":"monthly","purpose":"subscription","channel":"web"} }
    """
    email = (body.get("email") or "").strip()

    # style A
    account_id = (body.get("account_id") or "").strip()
    plan_code = (body.get("plan_code") or "").strip().lower()

    # style B
    md = body.get("metadata") or {}
    if isinstance(md, dict):
        account_id = account_id or (md.get("account_id") or "").strip()
        plan_code = plan_code or (md.get("plan_code") or "").strip().lower()

    # amount: we will compute from plan_code if available (safer),
    # but if plan_code missing we can fall back to amount_kobo.
    amount_kobo = body.get("amount_kobo")
    if amount_kobo is None:
        # some clients may send "amount" already in kobo
        amount_kobo = body.get("amount")

    currency = (body.get("currency") or "").strip() or None

    # keep full metadata (merge)
    merged_md: Dict[str, Any] = {}
    if isinstance(md, dict):
        merged_md.update(md)

    # also include server-sourced fields later
    return account_id or None, plan_code or None, email or None, (int(amount_kobo) if amount_kobo is not None else None), currency, merged_md


@paystack_bp.post("/paystack/init")
def paystack_init():
    body: Dict[str, Any] = request.get_json(silent=True) or {}

    account_id, plan_code, email, amount_kobo_in, currency, metadata = _extract_init_fields(body)

    if not email:
        return _json_error(400, "email_required")

    if not account_id:
        return _json_error(400, "account_id_required")

    # Strongly prefer plan_code -> server decides price (prevents tampering)
    amount_kobo: Optional[int] = None
    used_plan_code: Optional[str] = None

    if plan_code:
        plan = get_plan(plan_code)
        if not plan or not plan.get("active", True):
            return _json_error(400, "invalid_plan")

        amount_naira = int(plan.get("price") or 0)
        if amount_naira <= 0:
            return _json_error(400, "invalid_plan_price")

        amount_kobo = amount_naira * 100
        used_plan_code = plan_code
    else:
        # fallback: accept amount_kobo only if plan_code not provided
        if amount_kobo_in is None or int(amount_kobo_in) <= 0:
            return _json_error(400, "plan_code_or_amount_kobo_required")
        amount_kobo = int(amount_kobo_in)

    reference = create_reference("NTG")

    # finalize metadata (what we rely on later)
    metadata = metadata or {}
    metadata.update(
        {
            "account_id": account_id,
            "plan_code": used_plan_code or metadata.get("plan_code"),
            "purpose": metadata.get("purpose") or "subscription",
            "channel": metadata.get("channel") or "web",
        }
    )

    try:
        init_data = initialize_transaction(
            email=email,
            amount_kobo=amount_kobo,
            reference=reference,
            metadata=metadata,
            currency=currency,
        )
        d = init_data.get("data") or {}

        # store initiated transaction (best-effort)
        try:
            _sb().table("paystack_transactions").insert(
                {
                    "reference": reference,
                    "account_id": account_id,
                    "plan_code": used_plan_code,
                    "amount_kobo": amount_kobo,
                    "currency": d.get("currency") or (currency or "NGN"),
                    "status": "initiated",
                    "authorization_url": d.get("authorization_url"),
                    "access_code": d.get("access_code"),
                    "raw": init_data,
                }
            ).execute()
        except Exception:
            pass

        return (
            jsonify(
                {
                    "ok": True,
                    "authorization_url": d.get("authorization_url"),
                    "access_code": d.get("access_code"),
                    "reference": reference,
                }
            ),
            200,
        )

    except (PaystackError, ValueError) as e:
        return _json_error(400, str(e))
    except Exception as e:
        # ensure we never return blank bodies
        return _json_error(500, "init_unexpected_error", detail=str(e))


@paystack_bp.get("/paystack/verify/<reference>")
def paystack_verify(reference: str):
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
            return _json_error(400, "payment_not_successful", paystack_status=status)

        if not account_id or not plan_code:
            return _json_error(400, "missing_metadata", metadata=metadata)

        sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")
        return jsonify({"ok": True, "reference": reference, "subscription": sub}), 200

    except (PaystackError, ValueError) as e:
        return _json_error(400, str(e))
    except Exception as e:
        return _json_error(500, "verify_unexpected_error", detail=str(e))


@paystack_bp.post("/paystack/webhook")
def paystack_webhook():
    """
    Paystack will POST events here.
    We verify the signature and process `charge.success`.
    """
    raw = request.get_data(cache=False) or b""
    sig = request.headers.get("x-paystack-signature", "") or ""

    if not verify_webhook_signature(raw, sig):
        return _json_error(401, "invalid_signature")

    evt = request.get_json(silent=True) or {}
    event = (evt.get("event") or "").strip()
    data = evt.get("data") or {}

    # only handle the events you want
    if event != "charge.success":
        return jsonify({"ok": True, "ignored": True, "event": event}), 200

    reference = (data.get("reference") or "").strip()
    status = (data.get("status") or "").lower()
    metadata = data.get("metadata") or {}

    account_id = (metadata.get("account_id") or "").strip()
    plan_code = (metadata.get("plan_code") or "").strip().lower()

    if not reference:
        return _json_error(400, "missing_reference_in_webhook")

    # idempotency: if already marked success, do nothing
    try:
        existing = (
            _sb()
            .table("paystack_transactions")
            .select("reference,status,paystack_status")
            .eq("reference", reference)
            .limit(1)
            .execute()
        )
        rows = (existing.data or []) if hasattr(existing, "data") else []
        if rows and (rows[0].get("status") == "success" or (rows[0].get("paystack_status") or "").lower() == "success"):
            return jsonify({"ok": True, "duplicate": True}), 200
    except Exception:
        pass

    # update tx (best-effort)
    try:
        _sb().table("paystack_transactions").upsert(
            {
                "reference": reference,
                "account_id": account_id or None,
                "plan_code": plan_code or None,
                "paystack_status": status,
                "status": "success" if status == "success" else "failed",
                "raw": evt,
            },
            on_conflict="reference",
        ).execute()
    except Exception:
        pass

    if status != "success":
        return jsonify({"ok": True, "status": status}), 200

    # activate subscription if we have metadata
    if account_id and plan_code:
        try:
            activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")
        except Exception:
            # don't fail webhook
            pass

    return jsonify({"ok": True}), 200
