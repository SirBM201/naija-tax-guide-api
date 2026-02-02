# app/routes/webhooks.py
import os
import hmac
import hashlib
import json
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify

from ..services.subscriptions_service import handle_payment_success

bp = Blueprint("webhooks", __name__)

# -----------------------------
# Paystack
# -----------------------------
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", "").strip()

def _verify_paystack_signature(raw_body: bytes, signature: str) -> bool:
    if not PAYSTACK_WEBHOOK_SECRET:
        return False
    digest = hmac.new(
        PAYSTACK_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha512
    ).hexdigest()
    return hmac.compare_digest(digest, signature or "")

@bp.post("/webhooks/paystack")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    # In production, enforce signature
    if PAYSTACK_WEBHOOK_SECRET and not _verify_paystack_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    event = request.json or {}
    event_id = event.get("id") or event.get("event_id")
    event_type = (event.get("event") or "").lower()
    data = event.get("data") or {}

    if event_type not in ("charge.success",):
        return jsonify({"ok": True, "ignored": True, "event": event_type})

    meta = data.get("metadata") or {}
    account_id = (meta.get("account_id") or "").strip()
    plan_code = (meta.get("plan_code") or "").strip()

    reference = data.get("reference")
    amount_kobo = data.get("amount")
    currency = data.get("currency", "NGN")

    out = handle_payment_success({
        "event_id": event_id,
        "provider": "paystack",
        "reference": reference,
        "account_id": account_id,
        "plan_code": plan_code,
        "amount_kobo": amount_kobo,
        "currency": currency,
        "raw": event,
    })

    return jsonify(out), (200 if out.get("ok") else 400)

# -----------------------------
# WhatsApp Cloud API (Meta)
# -----------------------------
WA_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
# If you use app secret-based signature verification:
WA_APP_SECRET = os.getenv("WHATSAPP_APP_SECRET", "").strip()

def _verify_meta_signature(raw: bytes, sig_header: str) -> bool:
    """
    Meta may send header: X-Hub-Signature-256: sha256=...
    Only enable if you set WHATSAPP_APP_SECRET.
    """
    if not WA_APP_SECRET:
        return True  # skip if not configured
    if not sig_header or "=" not in sig_header:
        return False
    algo, sig = sig_header.split("=", 1)
    if algo.strip().lower() != "sha256":
        return False
    digest = hmac.new(WA_APP_SECRET.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, sig.strip())

@bp.get("/webhooks/whatsapp")
def whatsapp_verify():
    """
    Meta webhook verification
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and WA_VERIFY_TOKEN and token == WA_VERIFY_TOKEN:
        return challenge, 200
    return "forbidden", 403

@bp.post("/webhooks/whatsapp")
def whatsapp_inbound():
    raw = request.get_data() or b""
    sig = request.headers.get("X-Hub-Signature-256", "")

    if not _verify_meta_signature(raw, sig):
        return jsonify({"ok": False, "error": "invalid_signature"}), 401

    payload = request.json or {}

    # TODO: route into your WA handler/service.
    # For now we just ack and log minimal safe info.
    # You will parse messages under: entry -> changes -> value -> messages
    return jsonify({"ok": True}), 200

# -----------------------------
# Telegram Bot API webhook
# -----------------------------
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

def _verify_telegram_secret() -> bool:
    """
    If you configured secret token when setting webhook:
    Telegram will send header: X-Telegram-Bot-Api-Secret-Token
    """
    if not TELEGRAM_WEBHOOK_SECRET:
        return True
    got = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    return hmac.compare_digest(got or "", TELEGRAM_WEBHOOK_SECRET)

@bp.post("/webhooks/telegram")
def telegram_inbound():
    if not _verify_telegram_secret():
        return jsonify({"ok": False, "error": "invalid_secret"}), 401

    payload = request.json or {}

    # TODO: route into your Telegram handler/service.
    # Telegram inbound messages come under: message / edited_message / callback_query etc.
    return jsonify({"ok": True}), 200

# -----------------------------
# Placeholders for later (Messenger / Instagram / Email)
# -----------------------------
@bp.post("/webhooks/messenger")
def messenger_inbound():
    # TODO: implement Meta Messenger webhook verification + parsing
    return jsonify({"ok": True, "todo": True}), 200

@bp.post("/webhooks/instagram")
def instagram_inbound():
    # TODO: implement IG webhook verification + parsing
    return jsonify({"ok": True, "todo": True}), 200

@bp.post("/webhooks/email")
def email_inbound():
    # TODO: depends on your provider (SendGrid inbound parse, Mailgun routes, SES, etc.)
    return jsonify({"ok": True, "todo": True}), 200
