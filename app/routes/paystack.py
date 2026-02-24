# app/routes/paystack.py
from __future__ import annotations

import os
import hmac
import hashlib
from typing import Any, Dict

from flask import Blueprint, jsonify, request

from app.services.subscriptions_service import activate_subscription_now  # you already have this working

# IMPORTANT:
# - attribute name MUST be paystack_bp (because your loader looks for it)
# - blueprint "name" MUST be unique to avoid duplicate blueprint name collisions
paystack_bp = Blueprint("paystack_webhooks", __name__)


def _get_secret() -> str:
    return (os.getenv("PAYSTACK_WEBHOOK_SECRET") or "").strip()


def _verify_paystack_signature(raw_body: bytes, header_sig: str, secret: str) -> bool:
    if not secret or not header_sig:
        return False
    computed = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
    # constant-time compare
    return hmac.compare_digest(computed, header_sig.strip().lower())


@paystack_bp.post("/webhooks/paystack")
def paystack_webhook():
    secret = _get_secret()
    raw = request.get_data(cache=False, as_text=False) or b""
    sig = (request.headers.get("x-paystack-signature") or "").strip()

    # Optional: allow bypass in dev if explicitly enabled (recommended OFF in prod)
    allow_dev_bypass = (os.getenv("PAYSTACK_DEV_BYPASS", "").strip().lower() in {"1", "true", "yes"})
    if not allow_dev_bypass:
        if not _verify_paystack_signature(raw, sig, secret):
            return jsonify({"ok": False, "error": "invalid_signature"}), 401

    try:
        payload: Dict[str, Any] = request.get_json(force=True, silent=False) or {}
        event = (payload.get("event") or "").strip()
        data = payload.get("data") or {}
        reference = (data.get("reference") or "").strip()

        meta = (data.get("metadata") or {}) if isinstance(data.get("metadata"), dict) else {}
        account_id = (meta.get("account_id") or "").strip()
        plan_code = (meta.get("plan_code") or "monthly").strip()
        upgrade_mode = (meta.get("upgrade_mode") or "now").strip()

        # Only process successful charge events (you can expand later)
        if event not in {"charge.success"}:
            return jsonify({"ok": True, "processed": False, "event": event}), 200

        if not account_id:
            return jsonify({"ok": False, "error": "missing_account_id"}), 400

        # Activate subscription NOW (your existing function)
        activation = activate_subscription_now(account_id=account_id, plan_code=plan_code, days=None)

        return jsonify({
            "ok": True,
            "processed": True,
            "event": event,
            "reference": reference,
            "account_id": account_id,
            "plan_code": plan_code,
            "upgrade_mode": upgrade_mode,
            "activation": activation,
        }), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@paystack_bp.get("/_debug/paystack")
def debug_paystack():
    # Safe debug: confirms routing + whether secret is set (does NOT reveal secret)
    return jsonify({
        "ok": True,
        "secret_set": bool(_get_secret()),
        "bypass_enabled": (os.getenv("PAYSTACK_DEV_BYPASS", "").strip().lower() in {"1", "true", "yes"}),
    }), 200
