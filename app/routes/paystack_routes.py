# app/routes/paystack_routes.py
import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests
from flask import Blueprint, request, jsonify

bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip()  # e.g. https://xxxx.koyeb.app


def _db():
    from app.db.supabase_client import supabase as get_supabase
    return get_supabase()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verify_paystack_signature(raw: bytes, signature: str) -> bool:
    if not PAYSTACK_WEBHOOK_SECRET:
        return False
    expected = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def _paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def _amount_kobo(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _normalize_phone(p: str) -> str:
    # You are using wa_phone as TEXT identity key across channels
    # We'll keep only digits and leading country code if present.
    s = "".join(ch for ch in (p or "").strip() if ch.isdigit())
    return s


# -----------------------------
# TOP-UP: Initialize
# -----------------------------
@bp.post("/paystack/topup/initialize")
def paystack_topup_initialize():
    """
    Client sends:
      {
        "wa_phone": "2348012345678",
        "email": "user@example.com",
        "credits": 100,
        "amount_kobo": 200000
      }

    Returns:
      { ok: true, authorization_url, reference }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    wa_phone = _normalize_phone(body.get("wa_phone") or "")
    email = (body.get("email") or "").strip()
    credits = _int(body.get("credits"))
    amount_kobo = _amount_kobo(body.get("amount_kobo"))

    if not wa_phone:
        return jsonify({"ok": False, "message": "wa_phone is required"}), 400
    if not email or "@" not in email:
        return jsonify({"ok": False, "message": "Valid email is required"}), 400
    if credits <= 0:
        return jsonify({"ok": False, "message": "credits must be > 0"}), 400
    if amount_kobo <= 0:
        return jsonify({"ok": False, "message": "amount_kobo must be > 0"}), 400

    # Create an order reference locally (Paystack will also return one, but we control idempotency)
    reference = f"topup_{wa_phone}_{int(datetime.now(timezone.utc).timestamp())}"

    # Save pending order first (idempotent by reference)
    try:
        _db().table("ai_topup_orders").upsert(
            {
                "reference": reference,
                "wa_phone": wa_phone,
                "email": email,
                "amount_kobo": amount_kobo,
                "credits": credits,
                "status": "pending",
                "updated_at": _now_iso(),
            },
            on_conflict="reference",
        ).execute()
    except Exception as e:
        logging.exception("ai_topup_orders upsert failed: %s", e)
        return jsonify({"ok": False, "message": "Unable to create top-up order"}), 500

    callback_url = ""
    if APP_BASE_URL:
        callback_url = f"{APP_BASE_URL.rstrip('/')}/paystack/topup/callback"

    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "callback_url": callback_url or None,
        "metadata": {
            "purpose": "ai_topup",
            "wa_phone": wa_phone,
            "credits": credits,
        },
    }

    try:
        r = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=_paystack_headers(),
            data=json.dumps(payload),
            timeout=30,
        )
        if r.status_code not in (200, 201):
            logging.error("Paystack initialize failed: %s %s", r.status_code, r.text[:300])
            return jsonify({"ok": False, "message": "Paystack initialize failed"}), 502

        data = r.json() or {}
        if not data.get("status"):
            logging.error("Paystack initialize status false: %s", str(data)[:300])
            return jsonify({"ok": False, "message": "Paystack initialize failed"}), 502

        auth_url = (data.get("data") or {}).get("authorization_url")
        ref = (data.get("data") or {}).get("reference") or reference

        return jsonify({"ok": True, "authorization_url": auth_url, "reference": ref}), 200
    except Exception as e:
        logging.exception("Paystack initialize exception: %s", e)
        return jsonify({"ok": False, "message": "Paystack initialize exception"}), 500


# Optional callback (not required for webhook-driven confirmation)
@bp.get("/paystack/topup/callback")
def paystack_topup_callback():
    return jsonify({"ok": True, "message": "Top-up received. You can return to the app."}), 200


# -----------------------------
# PAYSTACK WEBHOOK (SUBSCRIPTIONS + TOPUPS)
# -----------------------------
@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_WEBHOOK_SECRET not set", 500

    if not _verify_paystack_signature(raw, sig):
        logging.warning("Invalid Paystack signature")
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_type = (event.get("event") or "").strip()
    data = event.get("data") or {}

    reference = (data.get("reference") or "").strip()
    metadata = data.get("metadata") or {}
    purpose = (metadata.get("purpose") or "").strip().lower()

    logging.info("Paystack webhook event=%s ref=%s purpose=%s", event_type, reference, purpose)

    # 1) Handle AI TOP-UP
    if purpose == "ai_topup":
        return _handle_ai_topup_event(event_type, data, event)

    # 2) Otherwise, this is your subscription webhook flow.
    # If you already have an existing subscription webhook handler elsewhere,
    # keep it there; but this file provides a safe fallback.
    try:
        from app.services.subscriptions import handle_subscription_paystack_event  # optional if you have it
        handle_subscription_paystack_event(event_type, data, event)
        return jsonify({"ok": True}), 200
    except Exception:
        # If you do NOT have subscriptions handler here, we do not break the webhook.
        logging.exception("Subscription webhook handler missing or failed (ignored).")
        return jsonify({"ok": True}), 200


def _handle_ai_topup_event(event_type: str, data: Dict[str, Any], full_event: Dict[str, Any]):
    """
    Only credit on successful charge.
    Paystack typical successful event types include:
      - charge.success
    We'll accept charge.success primarily.
    """
    if event_type not in ("charge.success", "transaction.success"):
        return jsonify({"ok": True}), 200

    status = (data.get("status") or "").lower()
    if status and status not in ("success", "successful"):
        return jsonify({"ok": True}), 200

    reference = (data.get("reference") or "").strip()
    metadata = data.get("metadata") or {}

    wa_phone = _normalize_phone(metadata.get("wa_phone") or "")
    credits = _int(metadata.get("credits"))
    amount_kobo = _amount_kobo(data.get("amount"))
    email = (data.get("customer") or {}).get("email") or (metadata.get("email") or "")

    if not reference or not wa_phone or credits <= 0:
        logging.warning("Top-up missing required metadata ref=%r wa_phone=%r credits=%r", reference, wa_phone, credits)
        return jsonify({"ok": True}), 200

    # Idempotency: if already marked paid, skip
    try:
        existing = (
            _db()
            .table("ai_topup_orders")
            .select("status")
            .eq("reference", reference)
            .limit(1)
            .execute()
        )
        rows = getattr(existing, "data", None) or []
        if rows and (rows[0].get("status") == "paid"):
            return jsonify({"ok": True}), 200
    except Exception:
        pass

    # Mark order paid
    try:
        _db().table("ai_topup_orders").upsert(
            {
                "reference": reference,
                "wa_phone": wa_phone,
                "email": (email or "")[:200],
                "amount_kobo": amount_kobo,
                "credits": credits,
                "status": "paid",
                "paid_at": _now_iso(),
                "raw_event": full_event,
                "updated_at": _now_iso(),
            },
            on_conflict="reference",
        ).execute()
    except Exception as e:
        logging.exception("ai_topup_orders paid upsert failed: %s", e)
        # still continue; we can attempt crediting

    # Credit the ledger for the ACTIVE subscription period
    try:
        _credit_paid_ledger(wa_phone=wa_phone, credits=credits)
    except Exception as e:
        logging.exception("credit ledger failed: %s", e)

    return jsonify({"ok": True}), 200


def _credit_paid_ledger(wa_phone: str, credits: int) -> None:
    """
    Add credits to the current subscription period ledger.
    We use user_subscriptions.expires_at as 'period_end'.
    """
    sub = None
    try:
        r = _db().table("user_subscriptions").select("*").eq("wa_phone", wa_phone).limit(1).execute()
        rows = getattr(r, "data", None) or []
        sub = rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription read failed: %s", e)
        sub = None

    if not sub or not sub.get("expires_at"):
        # If subscription is missing, we still store credits against "now" period_end (fallback)
        period_end = _now_iso()
        plan = "paid"
    else:
        period_end = str(sub.get("expires_at"))
        plan = (sub.get("plan") or "paid")

    # Read existing ledger
    ledger = None
    try:
        r2 = (
            _db()
            .table("ai_credit_ledger")
            .select("*")
            .eq("wa_phone", wa_phone)
            .eq("period_end", period_end)
            .limit(1)
            .execute()
        )
        rows2 = getattr(r2, "data", None) or []
        ledger = rows2[0] if rows2 else None
    except Exception:
        ledger = None

    current_total = int((ledger or {}).get("credits_total") or 0)
    current_used = int((ledger or {}).get("credits_used") or 0)

    new_total = current_total + int(credits)

    _db().table("ai_credit_ledger").upsert(
        {
            "wa_phone": wa_phone,
            "period_end": period_end,
            "plan": plan,
            "credits_total": new_total,
            "credits_used": current_used,
            "updated_at": _now_iso(),
        },
        on_conflict="wa_phone,period_end",
    ).execute()
