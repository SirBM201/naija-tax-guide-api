# app/routes/webhooks.py
import os
import json
import hmac
import hashlib
from typing import Any, Dict

from flask import Blueprint, request, jsonify

from ..services.subscriptions_service import handle_payment_success

bp = Blueprint("webhooks", __name__)

# -----------------------------
# Paystack
# -----------------------------
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", "").strip()


def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    """
    Paystack signature is HMAC-SHA512 of raw body using webhook secret.
    Header: x-paystack-signature
    """
    if not PAYSTACK_WEBHOOK_SECRET:
        return False
    digest = hmac.new(
        PAYSTACK_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(digest, signature or "")


def _ensure_dict(v: Any) -> Dict[str, Any]:
    """
    Paystack metadata is usually a dict, but can sometimes arrive as a JSON string.
    """
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _extract_account_and_plan(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Try multiple places Paystack might store metadata.
    We expect you set these during transaction initialization:
      metadata: { account_id, plan_code, upgrade_mode? }
    """
    meta = _ensure_dict((data or {}).get("metadata"))

    # Some people store values inside metadata.custom_fields
    custom_fields = meta.get("custom_fields")
    if isinstance(custom_fields, list):
        # custom_fields: [{display_name, variable_name, value}, ...]
        for item in custom_fields:
            try:
                k = (item.get("variable_name") or "").strip()
                v = (item.get("value") or "").strip()
                if k and k not in meta:
                    meta[k] = v
            except Exception:
                pass

    account_id = (meta.get("account_id") or "").strip()
    plan_code = (meta.get("plan_code") or "").strip()
    upgrade_mode = (meta.get("upgrade_mode") or "now").strip().lower()

    if upgrade_mode not in ("now", "at_expiry"):
        upgrade_mode = "now"

    return {
        "account_id": account_id,
        "plan_code": plan_code,
        "upgrade_mode": upgrade_mode,
        "metadata": meta,
    }


@bp.post("/webhooks/paystack")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    # If secret is set, enforce signature verification
    if PAYSTACK_WEBHOOK_SECRET and not _verify_paystack_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    event = request.get_json(silent=True) or {}
    event_id = event.get("id") or event.get("event_id")
    event_type = (event.get("event") or "").lower()
    data = event.get("data") or {}

    # Only process successful charges
    if event_type not in ("charge.success",):
        return jsonify({"ok": True, "ignored": True, "event": event_type}), 200

    extracted = _extract_account_and_plan(data)
    account_id = extracted["account_id"]
    plan_code = extracted["plan_code"]
    upgrade_mode = extracted["upgrade_mode"]

    if not account_id or not plan_code:
        # Don't crash the app; return clear error so you can see misconfigured metadata
        return jsonify(
            {
                "ok": False,
                "error": "missing_metadata",
                "message": "Paystack metadata must include account_id and plan_code.",
                "event_id": event_id,
                "reference": data.get("reference"),
                "metadata_seen": extracted.get("metadata"),
            }
        ), 400

    reference = data.get("reference")
    amount_kobo = data.get("amount")
    currency = data.get("currency", "NGN")

    out = handle_payment_success(
        {
            "event_id": event_id,
            "provider": "paystack",
            "reference": reference,
            "account_id": account_id,
            "plan_code": plan_code,
            "amount_kobo": amount_kobo,
            "currency": currency,
            "upgrade_mode": upgrade_mode,  # ✅ now supported
            "raw": event,
        }
    )

    return jsonify(out), (200 if out.get("ok") else 400)


# -----------------------------
# Meta (WhatsApp / Messenger / Instagram)
# -----------------------------
META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "").strip()


@bp.get("/webhooks/meta")
def meta_verify():
    """
    Meta webhook verification endpoint.
    Configure this URL in:
    - WhatsApp Cloud API webhooks
    - Facebook Messenger webhooks
    - Instagram webhooks
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and META_VERIFY_TOKEN and token == META_VERIFY_TOKEN:
        return challenge, 200
    return "forbidden", 403


@bp.post("/webhooks/meta")
def meta_events():
    """
    Receives Meta webhook events.
    For now: just acknowledge. Later we will route to:
    - WA inbound handler
    - Messenger inbound handler
    - Instagram DM inbound handler
    """
    payload = request.get_json(silent=True) or {}

    # TODO next: route by payload structure.
    # We'll implement in the inbound routes step.
    return jsonify({"ok": True}), 200
