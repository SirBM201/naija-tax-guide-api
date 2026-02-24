# app/routes/paystack.py
from __future__ import annotations

import hmac
import os
from hashlib import sha512
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.subscriptions_service import activate_subscription_now


# IMPORTANT:
# - Blueprint name MUST be unique to avoid your "Duplicate blueprint name detected" error
# - Export must match what app/__init__.py imports (see note below)
paystack_bp = Blueprint("paystack_webhooks", __name__)


def _raw_body_bytes() -> bytes:
    # must sign the RAW body bytes exactly
    return request.get_data(cache=False, as_text=False) or b""


def _get_sig_header() -> str:
    return (request.headers.get("x-paystack-signature") or "").strip().lower()


def _secret() -> str:
    return (os.getenv("PAYSTACK_WEBHOOK_SECRET") or "").strip()


def _bypass_enabled() -> bool:
    return (os.getenv("PAYSTACK_WEBHOOK_BYPASS", "") or "").strip().lower() in {"1", "true", "yes", "on"}


def _verify_signature_or_bypass() -> Optional[Dict[str, Any]]:
    """
    Return an error dict if invalid; return None if ok.
    """
    secret = _secret()
    sig = _get_sig_header()

    if _bypass_enabled():
        # Allow bypass in dev (ONLY) if secret is missing or you just want speed.
        # Keep it explicit via env var.
        return None

    if not secret:
        return {"ok": False, "error": "missing_webhook_secret"}

    if not sig:
        return {"ok": False, "error": "missing_signature"}

    expected = hmac.new(secret.encode("utf-8"), _raw_body_bytes(), sha512).hexdigest().lower()
    if not hmac.compare_digest(expected, sig):
        return {"ok": False, "error": "invalid_signature"}

    return None


@paystack_bp.get("/_debug/paystack")
def debug_paystack():
    return jsonify(
        {
            "ok": True,
            "bypass_enabled": _bypass_enabled(),
            "secret_set": bool(_secret()),
        }
    ), 200


@paystack_bp.post("/webhooks/paystack")
def paystack_webhook():
    verr = _verify_signature_or_bypass()
    if verr is not None:
        return jsonify(verr), 400

    try:
        payload = request.get_json(silent=True) or {}
        event = (payload.get("event") or "").strip()
        data = payload.get("data") or {}
        reference = (data.get("reference") or "").strip()
        metadata = data.get("metadata") or {}

        account_id = (metadata.get("account_id") or "").strip()
        plan_code = (metadata.get("plan_code") or "monthly").strip()
        upgrade_mode = (metadata.get("upgrade_mode") or "now").strip()

        # Minimal idempotency guard (recommended):
        # If you already have a paystack_events table, use it.
        # If not, you can skip this block, but duplicates can happen in production.
        try:
            # upsert event record by reference if your table exists
            supabase.table("paystack_events").upsert(
                {"reference": reference, "event": event, "account_id": account_id},
                on_conflict="reference",
            ).execute()
        except Exception:
            pass

        processed = False
        activation = {}

        # Only act on charge.success (extend later)
        if event == "charge.success":
            activation = activate_subscription_now(
                account_id=account_id,
                plan_code=plan_code,
                days=None,  # let service decide from plan
            )
            processed = bool(activation.get("ok") and activation.get("activated"))

        return jsonify(
            {
                "ok": True,
                "processed": processed,
                "event": event,
                "reference": reference,
                "account_id": account_id,
                "plan_code": plan_code,
                "upgrade_mode": upgrade_mode,
                "activation": activation,
            }
        ), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
