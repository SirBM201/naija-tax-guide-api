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


def _verify_signature(raw: bytes, signature: str) -> bool:
    if not PAYSTACK_WEBHOOK_SECRET:
        return False
    expected = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


def _is_active_paid_subscription(sub: Optional[Dict[str, Any]]) -> bool:
    if not sub:
        return False

    status = (sub.get("status") or "").strip().lower()
    if status and status not in ("active", "paid"):
        return False

    exp = sub.get("expires_at")
    if not exp:
        return False

    try:
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        return exp_dt > datetime.now(timezone.utc)
    except Exception:
        return False


def _get_subscription(wa_phone: str) -> Optional[Dict[str, Any]]:
    try:
        r = _db().table("user_subscriptions").select("*").eq("wa_phone", wa_phone).limit(1).execute()
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None


# ------------------------------------------------------------
# LOCKED TOPUP PACKAGES (EDIT PRICES HERE)
# ------------------------------------------------------------
# Amounts are in Kobo (₦1 = 100 kobo)
TOPUP_PACKAGES: Dict[str, Dict[str, Any]] = {
    "TOPUP_100": {
        "package_code": "TOPUP_100",
        "title": "100 AI Credits",
        "credits": 100,
        "amount_kobo": 200_00,  # ₦200.00 (example)
        "currency": "NGN",
    },
    "TOPUP_300": {
        "package_code": "TOPUP_300",
        "title": "300 AI Credits",
        "credits": 300,
        "amount_kobo": 500_00,  # ₦500.00 (example)
        "currency": "NGN",
    },
    "TOPUP_1000": {
        "package_code": "TOPUP_1000",
        "title": "1000 AI Credits",
        "credits": 1000,
        "amount_kobo": 1500_00,  # ₦1,500.00 (example)
        "currency": "NGN",
    },
}


def _get_topup_package(code: str) -> Optional[Dict[str, Any]]:
    if not code:
        return None
    return TOPUP_PACKAGES.get(code.strip().upper())


@bp.get("/paystack/health")
def paystack_health():
    return jsonify({"ok": True, "service": "paystack"}), 200


@bp.get("/paystack/topup/packages")
def paystack_topup_packages():
    return jsonify({"ok": True, "packages": list(TOPUP_PACKAGES.values())}), 200


# -----------------------------
# TOP-UP: Initialize (LOCKED + PAID-ONLY)
# -----------------------------
@bp.post("/paystack/topup/initialize")
def paystack_topup_initialize():
    """
    Request JSON (LOCKED PACKAGES):
      {
        "wa_phone": "2348012345678",
        "email": "user@example.com",
        "package_code": "TOPUP_300"
      }

    Rules:
      - Only active paid subscribers can top up.
      - Free users must upgrade (no top-up).

    Response:
      { ok: true, authorization_url, reference, credits, amount_kobo, package_code }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}

    wa_phone = _normalize_phone(body.get("wa_phone") or "")
    email = (body.get("email") or "").strip()
    package_code = (body.get("package_code") or "").strip().upper()

    if not wa_phone:
        return jsonify({"ok": False, "message": "wa_phone is required"}), 400
    if not email or "@" not in email:
        return jsonify({"ok": False, "message": "Valid email is required"}), 400

    # PAID-ONLY GUARD
    sub = _get_subscription(wa_phone)
    if not _is_active_paid_subscription(sub):
        return jsonify(
            {
                "ok": False,
                "message": "Top-up is only available to active subscribers. Please upgrade first.",
                "action": "upgrade",
                "reason": "not_subscribed_or_expired",
            }
        ), 403

    pkg = _get_topup_package(package_code)
    if not pkg:
        return jsonify({"ok": False, "message": "Invalid package_code"}), 400

    credits = int(pkg["credits"])
    amount_kobo = int(pkg["amount_kobo"])

    reference = f"topup_{wa_phone}_{package_code}_{int(datetime.now(timezone.utc).timestamp())}"

    # store pending order first
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
            "package_code": package_code,
        },
    }

    try:
        r = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers=_headers(),
            data=json.dumps(payload),
            timeout=30,
        )

        if r.status_code not in (200, 201):
            logging.error("Paystack initialize failed: %s %s", r.status_code, r.text[:300])
            return jsonify({"ok": False, "message": "Paystack initialize failed"}), 502

        resp = r.json() or {}
        if not resp.get("status"):
            logging.error("Paystack initialize status false: %s", str(resp)[:300])
            return jsonify({"ok": False, "message": "Paystack initialize failed"}), 502

        d = resp.get("data") or {}
        return jsonify(
            {
                "ok": True,
                "authorization_url": d.get("authorization_url"),
                "reference": d.get("reference") or reference,
                "credits": credits,
                "amount_kobo": amount_kobo,
                "package_code": package_code,
            }
        ), 200

    except Exception as e:
        logging.exception("Paystack initialize exception: %s", e)
        return jsonify({"ok": False, "message": "Paystack initialize exception"}), 500


@bp.get("/paystack/topup/callback")
def paystack_topup_callback():
    return jsonify({"ok": True, "message": "Top-up received. You can return to the app."}), 200


# -----------------------------
# PAYSTACK WEBHOOK (TOPUP + SUBSCRIPTIONS)
# -----------------------------
@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_WEBHOOK_SECRET not set", 500

    if not _verify_signature(raw, sig):
        logging.warning("Invalid Paystack signature")
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_type = (event.get("event") or "").strip()
    data = event.get("data") or {}
    metadata = data.get("metadata") or {}
    purpose = (metadata.get("purpose") or "").strip().lower()

    reference = (data.get("reference") or "").strip()
    logging.info("Paystack webhook event=%s purpose=%s ref=%s", event_type, purpose, reference)

    if purpose == "ai_topup":
        return _handle_topup(event_type, data, event)

    # Subscription events (optional handler you may already have)
    try:
        from app.services.subscriptions import handle_subscription_paystack_event  # optional
        handle_subscription_paystack_event(event_type, data, event)
        return jsonify({"ok": True}), 200
    except Exception:
        logging.exception("Subscription webhook handler missing/failed (ignored).")
        return jsonify({"ok": True}), 200


def _handle_topup(event_type: str, data: Dict[str, Any], full_event: Dict[str, Any]):
    if event_type not in ("charge.success", "transaction.success"):
        return jsonify({"ok": True}), 200

    status = (data.get("status") or "").lower()
    if status and status not in ("success", "successful"):
        return jsonify({"ok": True}), 200

    reference = (data.get("reference") or "").strip()
    metadata = data.get("metadata") or {}

    wa_phone = _normalize_phone(metadata.get("wa_phone") or "")
    credits = _int(metadata.get("credits"))
    package_code = (metadata.get("package_code") or "").strip().upper()
    amount_kobo = _int(data.get("amount"))
    email = (data.get("customer") or {}).get("email") or ""

    if not reference or not wa_phone or credits <= 0 or not package_code:
        logging.warning(
            "Topup missing metadata ref=%r wa_phone=%r credits=%r package=%r",
            reference, wa_phone, credits, package_code
        )
        return jsonify({"ok": True}), 200

    # SECURITY: verify the credited values match the LOCKED package mapping
    pkg = _get_topup_package(package_code)
    if not pkg:
        logging.warning("Topup webhook invalid package_code=%r", package_code)
        return jsonify({"ok": True}), 200

    if int(pkg["credits"]) != int(credits):
        logging.warning("Topup credits mismatch. pkg=%s got=%s", pkg["credits"], credits)
        return jsonify({"ok": True}), 200

    if int(pkg["amount_kobo"]) != int(amount_kobo):
        logging.warning("Topup amount mismatch. pkg=%s got=%s", pkg["amount_kobo"], amount_kobo)
        return jsonify({"ok": True}), 200

    # Idempotency: if already paid, skip
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
        logging.exception("ai_topup_orders upsert paid failed: %s", e)

    # Credit ledger (current subscription period)
    _credit_ledger(wa_phone, credits)

    return jsonify({"ok": True}), 200


def _credit_ledger(wa_phone: str, credits: int) -> None:
    sub = _get_subscription(wa_phone)

    if sub and sub.get("expires_at"):
        period_end = str(sub.get("expires_at"))
        plan = sub.get("plan") or "paid"
    else:
        period_end = _now_iso()
        plan = "paid"

    # Read current ledger
    try:
        r2 = (
            _db()
            .table("ai_credit_ledger")
            .select("credits_total,credits_used")
            .eq("wa_phone", wa_phone)
            .eq("period_end", period_end)
            .limit(1)
            .execute()
        )
        rows2 = getattr(r2, "data", None) or []
        row = rows2[0] if rows2 else {"credits_total": 0, "credits_used": 0}
    except Exception:
        row = {"credits_total": 0, "credits_used": 0}

    total = _int(row.get("credits_total"))
    used = _int(row.get("credits_used"))
    new_total = total + int(credits)

    _db().table("ai_credit_ledger").upsert(
        {
            "wa_phone": wa_phone,
            "period_end": period_end,
            "plan": plan,
            "credits_total": new_total,
            "credits_used": used,
            "updated_at": _now_iso(),
        },
        on_conflict="wa_phone,period_end",
    ).execute()
