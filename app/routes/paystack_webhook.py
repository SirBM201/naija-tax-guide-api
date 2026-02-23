# app/routes/paystack_webhook.py
from __future__ import annotations

from typing import Any, Dict, Optional
from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.paystack_service import verify_webhook_signature
from app.services.subscriptions_service import activate_subscription_now

bp = Blueprint("paystack_webhook", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _safe_update_paystack_tx(reference: str, payload: Dict[str, Any], status: str) -> None:
    """
    paystack_transactions schema varies across versions.
    We attempt richer updates first, then fall back to minimal fields.
    """
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

    # fallback: minimal
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
    """
    paystack_events columns you have:
      id (bigint), event_id, event_type, reference, payload(jsonb), created_at(default now)
    """
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


@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = (request.headers.get("x-paystack-signature") or "").strip()

    if not verify_webhook_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    event_type = (payload.get("event") or "").strip()
    event_id = (payload.get("id") or "").strip()

    data = payload.get("data") or {}
    reference = (data.get("reference") or "").strip()
    status = (data.get("status") or "").strip().lower()
    metadata = data.get("metadata") or {}

    # 1) Idempotency: if event already processed, ack OK fast
    if event_id and _event_exists(event_id):
        return jsonify({"ok": True, "deduped": True}), 200

    # 2) Persist event (best-effort)
    _insert_event(event_id=event_id, event_type=event_type, reference=reference, payload=payload)

    # 3) Update transaction row (best-effort)
    _safe_update_paystack_tx(reference=reference, payload=payload, status=status)

    # 4) Activate on success events only
    success_events = {"charge.success", "subscription.create", "invoice.payment_succeeded"}
    if event_type in success_events and status == "success":
        account_id = (metadata.get("account_id") or "").strip()
        plan_code = (metadata.get("plan_code") or "").strip().lower()

        if account_id and plan_code:
            # This call is now FK-safe (resolves to accounts.id internally)
            _ = activate_subscription_now(
                account_id=account_id,
                plan_code=plan_code,
                status="active",
                provider="paystack",
                provider_ref=reference or None,
            )

    return jsonify({"ok": True}), 200
