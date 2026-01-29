# app/routes/paystack_routes.py
import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import requests
from flask import Blueprint, request, jsonify, redirect

from app.db.supabase_client import supabase  # NOTE: this is a FUNCTION: supabase()

bp = Blueprint("paystack", __name__)

# -----------------------------
# ENV
# -----------------------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
# If you don't set PAYSTACK_WEBHOOK_SECRET, it falls back to PAYSTACK_SECRET_KEY
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()

# Frontend base URL (IMPORTANT)
# Local:  http://localhost:3000
# Prod:   https://thecre8hub.com
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "").strip()

# Optional: your API base URL (for debugging only)
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

# -----------------------------
# TOP-UP PACKAGES (LOCKED)
# -----------------------------
TOPUP_PACKAGES: Dict[str, Dict[str, Any]] = {
    "TOPUP_100": {"package_code": "TOPUP_100", "title": "100 AI Credits", "credits": 100, "amount_kobo": 200_00, "currency": "NGN"},
    "TOPUP_300": {"package_code": "TOPUP_300", "title": "300 AI Credits", "credits": 300, "amount_kobo": 500_00, "currency": "NGN"},
    "TOPUP_1000": {"package_code": "TOPUP_1000", "title": "1000 AI Credits", "credits": 1000, "amount_kobo": 1500_00, "currency": "NGN"},
}


# -----------------------------
# Helpers
# -----------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _headers() -> Dict[str, str]:
    if not PAYSTACK_SECRET_KEY:
        return {}
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


def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


def _get_plan(plan: str) -> Optional[Dict[str, Any]]:
    if not plan:
        return None
    return PLANS.get(plan.strip().lower())


def _get_topup_package(code: str) -> Optional[Dict[str, Any]]:
    if not code:
        return None
    return TOPUP_PACKAGES.get(code.strip().upper())


def _frontend_url(path: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Build a frontend URL from FRONTEND_BASE_URL, plus optional query params.
    """
    base = (FRONTEND_BASE_URL or "").rstrip("/")
    if not base:
        return ""
    p = "/" + path.lstrip("/")
    if params:
        return f"{base}{p}?{urlencode(params)}"
    return f"{base}{p}"


def _get_subscription(phone: str) -> Optional[Dict[str, Any]]:
    try:
        r = supabase().table("user_subscriptions").select("*").eq("wa_phone", phone).limit(1).execute()
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None


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
        return exp_dt > _now()
    except Exception:
        return False


# -----------------------------
# Health
# -----------------------------
@bp.get("/paystack/health")
def paystack_health():
    return jsonify({"ok": True, "service": "paystack"}), 200


# -----------------------------
# SUBSCRIPTION: Initialize
# -----------------------------
@bp.post("/paystack/subscription/initialize")
def paystack_subscription_initialize():
    """
    Request JSON:
      {
        "phone": "2348012345678",
        "email": "user@example.com",
        "plan": "monthly" | "quarterly" | "yearly"
      }

    Response:
      { ok: true, authorization_url, reference }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    phone = _normalize_phone(body.get("phone") or body.get("wa_phone") or "")
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
        supabase().table("user_subscriptions").upsert(
            {
                "wa_phone": phone,
                "email": email[:200],
                "plan": plan,
                "status": "pending",
                "amount_kobo": amount_kobo,
