# app/routes/paystack_routes.py
import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

import requests
from flask import Blueprint, request, jsonify

from app.db.supabase_client import supabase  # ✅ IMPORTANT: import the CLIENT (not a function)

bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()

# NOTE:
# This is your BACKEND base URL on Koyeb (API). It's optional for callback endpoints.
APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip()  # e.g. https://xxxx.koyeb.app


# -----------------------------
# Plans (NEW PRICES)
# -----------------------------
# Amounts are in Kobo (₦1 = 100 kobo)
PLANS: Dict[str, Dict[str, Any]] = {
    "monthly": {"plan": "monthly", "amount_kobo": 3300_00, "duration_days": 30, "currency": "NGN"},
    "quarterly": {"plan": "quarterly", "amount_kobo": 9000_00, "duration_days": 90, "currency": "NGN"},
    "yearly": {"plan": "yearly", "amount_kobo": 33000_00, "duration_days": 365, "currency": "NGN"},
}

# ------------------------------------------------------------
# LOCKED TOPUP PACKAGES (EDIT PRICES HERE)
# ------------------------------------------------------------
TOPUP_PACKAGES: Dict[str, Dict[str, Any]] = {
    "TOPUP_100": {
        "package_code": "TOPUP_100",
        "title": "100 AI Credits",
        "credits": 100,
        "amount_kobo": 200_00,
        "currency": "NGN",
    },
    "TOPUP_300": {
        "package_code": "TOPUP_300",
        "title": "300 AI Credits",
        "credits": 300,
        "amount_kobo": 500_00,
        "currency": "NGN",
    },
    "TOPUP_1000": {
        "package_code": "TOPUP_1000",
        "title": "1000 AI Credits",
        "credits": 1000,
        "amount_kobo": 1500_00,
        "currency": "NGN",
    },
}


# -----------------------------
# Helpers
# -----------------------------
def _db():
    # ✅ Return the Supabase client object (same style as ask.py / subscription_routes.py)
    return supabase


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}


def _verify_signature(raw: bytes, signature: str) -> bool:
    if not PAYSTACK_WEBHOOK_SECRET:
        return False
    expected = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature or "")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _normalize_phone(p: Any) -> str:
    return "".join(ch for ch in str(p or "").strip() if ch.isdigit())


def _get_subscription(phone: str) -> Optional[Dict[str, Any]]:
    try:
        r = _db().table("user_subscriptions").select("*").eq("wa_phone", phone).limit(1).execute()
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None


def _is_active_paid_subscription(sub: Optional[Dict[str, Any]]) -> bool:
    if not sub:
        return False

    status = (sub.get("status") or "").strip().lower()
    # accept both active and paid
    if status and status not in ("active", "paid"):
        return False

    exp = sub.get("expires_at")
    if not exp:
        return False

    try:
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        return exp_dt > _now()
    except Exception:
        return False


def _get_plan(plan: str) -> Optional[Dict[str, Any]]:
    if not plan:
        return None
    return PLANS.get(plan.strip().lower())


def _get_topup_package(code: str) -> Optional[Dict[str, Any]]:
    if not code:
        return None
    return TOPUP_PACKAGES.get(code.strip().upper())


@bp.get("/paystack/health")
def paystack_health():
    return jsonify({"ok": True, "service": "paystack"}), 200


# -----------------------------
# SUBSCRIPTION: Initialize
# -----------------------------
@bp.post("/paystack/subscription/initialize")
def paystack_subscription_initialize():
    """
    Request JSON (frontend may send user_key):
      {
        "phone": "2348012345678" OR "wa_phone": "..." OR "user_key": "...",
        "email": "user@example.com",
        "plan": "monthly" | "quarterly" | "yearly"
      }

    Response:
      { ok: true, authorization_url, reference }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}

    # ✅ Accept all variants to avoid mismatch forever
    phone = _normalize_phone(body.get("phone") or body.get("wa_phone") or body.get("user_key") or "")
    email = (body.get("email") or "").strip()
    plan = (body.get("plan") or "").strip().lower()

    if not phone:
        return jsonify({"ok": False, "message": "phone is required"}), 400
    if not email or "@" not in email:
        return jsonify({"ok": False, "message": "Valid email is required"}), 400

    p = _get_plan(plan)
    if not p:
        return jsonify({"ok": False, "message": "Invalid plan"}), 400

    amount_kobo = int(p["amount_kobo"])
    duration_days = int(p["duration_days"])

    reference = f"sub_{plan}_{int(_now().timestamp())}_{phone[-6:]}"

    # Save pending subscription before redirect
    try:
        _db().table("user_subscriptions").upsert(
            {
                "wa_phone": phone,
                "email": email[:200],
                "plan": plan,
                "status": "pending",
                "amount_kobo": amount_kobo,
                "currency": p.get("currency", "NGN"),
                "duration_days": duration_days,
                "reference": reference,
                "paystack_reference": reference,
                "last_event": "initialize",
                "updated_at": _now_iso(),
            },
            on_conflict="wa_phone",
        ).execute()
    except Exception as e:
        logging.exception("user_subscriptions upsert pending failed: %s", e)
        return jsonify({"ok": False, "message": "Unable to create subscription"}), 500

    callback_url = ""
    if APP_BASE_URL:
        # This is optional — Paystack can redirect here after payment.
        callback_url = f"{APP_BASE_URL.rstrip('/')}/paystack/subscription/callback"

    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "callback_url": callback_url or None,
        "metadata": {
            "purpose": "subscription",
            "phone": phone,
            "plan": plan,
            "duration_days": duration_days,
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
                "plan": plan,
                "amount_kobo": amount_kobo,
                "label": plan,
            }
        ), 200

    except Exception as e:
        logging.exception("Paystack initialize exception: %s", e)
        return jsonify({"ok": False, "message": "Paystack initialize exception"}), 500


@bp.get("/paystack/subscription/callback")
def paystack_subscription_callback():
    return jsonify({"ok": True, "message": "Payment received. Return to the app to refresh status."}), 200


# -----------------------------
# SUBSCRIPTION: Verify (manual)
# -----------------------------
@bp.post("/paystack/subscription/verify")
def paystack_subscription_verify():
    """
    Request JSON:
      { "reference": "...", "phone": "234..." optional }

    Response:
      { ok: true, status, plan, expires_at, reference }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    reference = (body.get("reference") or body.get("paystack_reference") or "").strip()
    phone = _normalize_phone(body.get("phone") or body.get("wa_phone") or body.get("user_key") or "")

    if not reference:
        return jsonify({"ok": False, "message": "reference is required"}), 400

    try:
        vr = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=_headers(),
            timeout=30,
        )
        if vr.status_code != 200:
            logging.error("Paystack verify failed: %s %s", vr.status_code, vr.text[:300])
            return jsonify({"ok": False, "message": "Paystack verify failed"}), 502

        payload = vr.json() or {}
        if not payload.get("status"):
            return jsonify({"ok": False, "message": "Paystack verify returned status=false"}), 502

        data = payload.get("data") or {}
        paid_status = (data.get("status") or "").lower()
        if paid_status not in ("success", "successful"):
            return jsonify({"ok": False, "message": f"Payment not successful (status={paid_status})"}), 400

        md = data.get("metadata") or {}
        md_phone = _normalize_phone(md.get("phone") or "")
        md_plan = (md.get("plan") or "").strip().lower()
        md_days = _int(md.get("duration_days"), 0)

        final_phone = md_phone or phone
        if not final_phone:
            return jsonify({"ok": False, "message": "Missing phone (metadata or request)"}), 400

        p = _get_plan(md_plan) if md_plan else None
        if not p:
            row = _get_subscription(final_phone)
            md_plan = (row.get("plan") if row else "") or "monthly"
            p = _get_plan(md_plan)

        duration_days = md_days or int((p or {}).get("duration_days") or 30)
        expires_at = (_now() + timedelta(days=duration_days)).isoformat()

        _db().table("user_subscriptions").upsert(
            {
                "wa_phone": final_phone,
                "plan": md_plan,
                "status": "active",
                "expires_at": expires_at,
                "paystack_reference": reference,
                "reference": reference,
                "last_event": "verify_success",
                "updated_at": _now_iso(),
            },
            on_conflict="wa_phone",
        ).execute()

        return jsonify(
            {"ok": True, "status": "active", "plan": md_plan, "expires_at": expires_at, "reference": reference}
        ), 200

    except Exception as e:
        logging.exception("verify exception: %s", e)
        return jsonify({"ok": False, "message": "Verify exception"}), 500


# -----------------------------
# TOP-UP: Packages
# -----------------------------
@bp.get("/paystack/topup/packages")
def paystack_topup_packages():
    return jsonify({"ok": True, "packages": list(TOPUP_PACKAGES.values())}), 200


# -----------------------------
# TOP-UP: Initialize (LOCKED + PAID-ONLY)
# -----------------------------
@bp.post("/paystack/topup/initialize")
def paystack_topup_initialize():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}

    phone = _normalize_phone(body.get("phone") or body.get("wa_phone") or body.get("user_key") or "")
    email = (body.get("email") or "").strip()
    package_code = (body.get("package_code") or "").strip().upper()

    if not phone:
        return jsonify({"ok": False, "message": "phone is required"}), 400
    if not email or "@" not in email:
        return jsonify({"ok": False, "message": "Valid email is required"}), 400

    sub = _get_subscription(phone)
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
    reference = f"topup_{phone}_{package_code}_{int(_now().timestamp())}"

    try:
        _db().table("ai_topup_orders").upsert(
            {
                "reference": reference,
                "wa_phone": phone,
                "email": email[:200],
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
            "phone": phone,
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

    if purpose == "subscription":
        return _handle_subscription_webhook(event_type, data, event)

    return jsonify({"ok": True}), 200


def _handle_subscription_webhook(event_type: str, data: Dict[str, Any], full_event: Dict[str, Any]):
    if event_type not in ("charge.success", "transaction.success"):
        return jsonify({"ok": True}), 200

    status = (data.get("status") or "").lower()
    if status and status not in ("success", "successful"):
        return jsonify({"ok": True}), 200

    reference = (data.get("reference") or "").strip()
    md = data.get("metadata") or {}
    phone = _normalize_phone(md.get("phone") or "")
    plan = (md.get("plan") or "").strip().lower()
    duration_days = _int(md.get("duration_days"), 0)

    if not phone:
        logging.warning("Subscription webhook missing phone metadata ref=%r", reference)
        return jsonify({"ok": True}), 200

    p = _get_plan(plan) or _get_plan("monthly")
    duration_days = duration_days or int(p["duration_days"])
    expires_at = (_now() + timedelta(days=duration_days)).isoformat()

    _db().table("user_subscriptions").upsert(
        {
            "wa_phone": phone,
            "plan": plan or p["plan"],
            "status": "active",
            "expires_at": expires_at,
            "paystack_reference": reference,
            "reference": reference,
            "last_event": event_type,
            "updated_at": _now_iso(),
        },
        on_conflict="wa_phone",
    ).execute()

    return jsonify({"ok": True}), 200


def _handle_topup(event_type: str, data: Dict[str, Any], full_event: Dict[str, Any]):
    if event_type not in ("charge.success", "transaction.success"):
        return jsonify({"ok": True}), 200

    status = (data.get("status") or "").lower()
    if status and status not in ("success", "successful"):
        return jsonify({"ok": True}), 200

    reference = (data.get("reference") or "").strip()
    metadata = data.get("metadata") or {}

    phone = _normalize_phone(metadata.get("phone") or "")
    credits = _int(metadata.get("credits"))
    package_code = (metadata.get("package_code") or "").strip().upper()
    amount_kobo = _int(data.get("amount"))
    email = (data.get("customer") or {}).get("email") or ""

    if not reference or not phone or credits <= 0 or not package_code:
        logging.warning(
            "Topup missing metadata ref=%r phone=%r credits=%r package=%r",
            reference, phone, credits, package_code
        )
        return jsonify({"ok": True}), 200

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

    # mark order paid
    try:
        _db().table("ai_topup_orders").upsert(
            {
                "reference": reference,
                "wa_phone": phone,
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

    # credit ledger (optional)
    try:
        _db().table("ai_credit_ledger").insert(
            {"wa_phone": phone, "reference": reference, "credits": credits, "created_at": _now_iso()}
        ).execute()
    except Exception:
        pass

    return jsonify({"ok": True}), 200
