from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.paystack_service import verify_webhook_signature
from app.services.referral_service import (
    qualify_referral_after_successful_payment,
    reverse_rewards_for_payment_reference,
)
from app.services.subscriptions_service import activate_subscription_now

bp = Blueprint("paystack_webhook", __name__)


SUCCESS_EVENTS = {
    "charge.success",
    "subscription.create",
    "invoice.payment_succeeded",
}

REVERSAL_EVENTS = {
    "charge.dispute.create",
    "charge.dispute.reminder",
    "charge.dispute.resolve",
    "refund.processed",
    "refund.failed",
    "refund.pending",
}


def _sb():
    return supabase() if callable(supabase) else supabase


def _safe_update_paystack_tx(reference: str, payload: Dict[str, Any], status: str) -> None:
    if not reference:
        return

    try:
        _sb().table("paystack_transactions").update(
            {
                "paystack_status": status,
                "raw": payload,
                "status": "success" if status == "success" else "failed",
            }
        ).eq("reference", reference).execute()
        return
    except Exception:
        pass

    try:
        _sb().table("paystack_transactions").update(
            {
                "raw": payload,
                "status": "success" if status == "success" else "failed",
            }
        ).eq("reference", reference).execute()
    except Exception:
        return


def _event_exists(event_id: str) -> bool:
    if not event_id:
        return False
    try:
        res = (
            _sb()
            .table("paystack_events")
            .select("id")
            .eq("event_id", event_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return bool(rows)
    except Exception:
        return False


def _insert_event(event_id: str, event_type: str, reference: Optional[str], payload: Dict[str, Any]) -> None:
    try:
        _sb().table("paystack_events").insert(
            {
                "event_id": event_id or "",
                "event_type": event_type or "",
                "reference": reference or None,
                "payload": payload,
            }
        ).execute()
    except Exception:
        return


def _extract_reference(data: Dict[str, Any]) -> str:
    return (data.get("reference") or data.get("transaction_reference") or "").strip()


def _extract_status(data: Dict[str, Any]) -> str:
    return (data.get("status") or "").strip().lower()


def _extract_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    md = data.get("metadata")
    return md if isinstance(md, dict) else {}


def _extract_account_id(metadata: Dict[str, Any]) -> str:
    return (metadata.get("account_id") or "").strip()


def _extract_plan_code(metadata: Dict[str, Any]) -> str:
    return (metadata.get("plan_code") or "").strip().lower()


def _handle_successful_payment(
    *,
    event_type: str,
    reference: str,
    status: str,
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    if event_type not in SUCCESS_EVENTS or status != "success":
        return {"ok": True, "skipped": True, "reason": "not_success_event"}

    account_id = _extract_account_id(metadata)
    plan_code = _extract_plan_code(metadata)

    if not account_id or not plan_code:
        return {
            "ok": True,
            "skipped": True,
            "reason": "missing_account_id_or_plan_code",
            "account_id": account_id,
            "plan_code": plan_code,
        }

    activation = activate_subscription_now(
        account_id=account_id,
        plan_code=plan_code,
    )

    referral = qualify_referral_after_successful_payment(
        paying_account_id=account_id,
        payment_reference=reference,
        plan_code=plan_code,
    )

    return {
        "ok": True,
        "activation": activation,
        "referral": referral,
    }


def _handle_reversal_event(
    *,
    event_type: str,
    reference: str,
) -> Dict[str, Any]:
    if event_type not in REVERSAL_EVENTS:
        return {"ok": True, "skipped": True, "reason": "not_reversal_event"}

    if not reference:
        return {"ok": True, "skipped": True, "reason": "missing_reference"}

    reversal = reverse_rewards_for_payment_reference(
        payment_reference=reference,
        reversal_reason=f"paystack_event:{event_type}",
    )
    return {
        "ok": True,
        "reversal": reversal,
    }


@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = (request.headers.get("x-paystack-signature") or "").strip()

    if not verify_webhook_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    event_type = str(payload.get("event") or "").strip()
    event_id = str(payload.get("id") or "").strip()

    data = payload.get("data") or {}
    reference = _extract_reference(data)
    status = _extract_status(data)
    metadata = _extract_metadata(data)

    if event_id and _event_exists(event_id):
        return jsonify({"ok": True, "deduped": True}), 200

    _insert_event(event_id=event_id, event_type=event_type, reference=reference, payload=payload)
    _safe_update_paystack_tx(reference=reference, payload=payload, status=status)

    success_outcome = _handle_successful_payment(
        event_type=event_type,
        reference=reference,
        status=status,
        metadata=metadata,
    )

    reversal_outcome = _handle_reversal_event(
        event_type=event_type,
        reference=reference,
    )

    return jsonify(
        {
            "ok": True,
            "event_type": event_type,
            "reference": reference,
            "success_outcome": success_outcome,
            "reversal_outcome": reversal_outcome,
        }
    ), 200

