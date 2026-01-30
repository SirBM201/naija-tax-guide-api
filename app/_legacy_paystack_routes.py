# app/paystack_routes.py
import os
import hmac
import hashlib
import logging
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests
from flask import Blueprint, request, jsonify
from supabase import create_client

log = logging.getLogger(__name__)

paystack_bp = Blueprint("paystack", __name__)

# -----------------------------
# ENV
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")
# If you set PAYSTACK_WEBHOOK_SECRET separately, it will be used; else secret key is used.
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY)

# Optional but recommended
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "")  # e.g. https://thecre8hub.com/payment/success

# Create supabase client once
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    log.warning("Supabase env vars missing. SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set.")
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# -----------------------------
# Time helpers
# -----------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()

def parse_iso(s: str) -> Optional[datetime]:
    try:
        # Handles "2026-01-10T00:00:00+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


# -----------------------------
# Plan duration fallback
# If you add duration_days column in public.plans, we will use it automatically.
# -----------------------------
FALLBACK_PLAN_DURATIONS_DAYS = {
    "basic": 30,       # monthly
    "standard": 90,    # quarterly
    "premium": 365,    # yearly
}

def get_plan_from_db(plan: str) -> Dict[str, Any]:
    """
    Reads plans from: public.plans
    Expected columns:
      - plan (text) [PK or unique]
      - title (text)
      - amount_kobo (int)
      - currency (text) e.g. NGN
    Optional:
      - duration_days (int)
    """
    res = (
        supabase
        .table("plans")
        .select("plan,title,amount_kobo,currency,duration_days")
        .eq("plan", plan)
        .single()
        .execute()
    )
    if not res.data:
        raise ValueError(f"Plan not found: {plan}")

    row = res.data
    if row.get("amount_kobo") is None:
        raise ValueError(f"Plan has no amount_kobo: {plan}")
    if not row.get("currency"):
        row["currency"] = "NGN"

    # duration_days is optional
    dur = row.get("duration_days")
    if dur is None:
        dur = FALLBACK_PLAN_DURATIONS_DAYS.get(plan)
    if dur is None:
        raise ValueError(f"duration_days missing for plan '{plan}' and no fallback available")

    row["duration_days"] = int(dur)
    row["amount_kobo"] = int(row["amount_kobo"])
    return row


# -----------------------------
# Subscription activation (idempotent + extend-safe)
# Table assumed: public.user_subscriptions
# Columns assumed (minimum):
#   - wa_phone (text, unique)
#   - plan (text)
#   - status (text)
#   - expires_at (timestamptz text acceptable)
#   - updated_at (timestamptz)
# Optional:
#   - started_at
# -----------------------------
def activate_or_extend_subscription(wa_phone: str, plan: str, duration_days: int) -> Dict[str, Any]:
    """
    If user has an active subscription that hasn't expired, extend from current expires_at.
    Else activate from now.
    """
    # Read existing
    existing = None
    try:
        r = (
            supabase
            .table("user_subscriptions")
            .select("wa_phone,plan,status,expires_at")
            .eq("wa_phone", wa_phone)
            .maybe_single()
            .execute()
        )
        existing = r.data
    except Exception as e:
        log.warning("Could not read existing subscription (will still upsert). Error: %s", e)

    base_time = now_utc()
    if existing and existing.get("expires_at"):
        exp_dt = parse_iso(existing["expires_at"]) if isinstance(existing["expires_at"], str) else None
        if exp_dt and exp_dt > base_time:
            base_time = exp_dt  # extend from current expiry

    new_expires = base_time + timedelta(days=int(duration_days))

    payload = {
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": iso(new_expires),
        "updated_at": iso(now_utc()),
        "started_at": iso(now_utc()),
    }

    supabase.table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()
    return payload


# -----------------------------
# PAYSTACK: Initialize Transaction
# -----------------------------
@paystack_bp.post("/paystack/initialize")
def paystack_initialize():
    """
    Request body JSON:
    {
      "wa_phone": "+234xxxxxxxxxx",
      "email": "user@email.com",
      "plan": "basic|standard|premium"
    }

    Response:
    {
      "status": true,
      "authorization_url": "...",
      "access_code": "...",
      "reference": "..."
    }
    """
    try:
        if not PAYSTACK_SECRET_KEY:
            return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

        body = request.get_json(silent=True) or {}
        wa_phone = (body.get("wa_phone") or "").strip()
        email = (body.get("email") or "").strip()
        plan = (body.get("plan") or "").strip().lower()

        if not wa_phone or not email or not plan:
            return jsonify({"ok": False, "error": "wa_phone, email, and plan are required"}), 400

        plan_row = get_plan_from_db(plan)
        amount_kobo = plan_row["amount_kobo"]          # already in kobo - DO NOT multiply
        currency = plan_row.get("currency", "NGN")

        reference = f"cre8_{uuid4().hex}"

        payload = {
            "email": email,
            "amount": amount_kobo,
            "currency": currency,
            "reference": reference,
            "metadata": {
                "wa_phone": wa_phone,
                "plan": plan,
                "plan_title": plan_row.get("title") or plan.upper(),
            }
        }

        # Optional callback URL (Paystack will redirect user here after payment)
        if PAYSTACK_CALLBACK_URL:
            payload["callback_url"] = PAYSTACK_CALLBACK_URL

        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            headers={
                "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )

        data = resp.json() if resp.content else {}
        if resp.status_code >= 400 or not data.get("status"):
            # Show Paystack message for easier debugging
            return jsonify({
                "ok": False,
                "error": "Paystack initialize failed",
                "paystack_status_code": resp.status_code,
                "paystack_response": data,
            }), 400

        # Return Paystack auth info
        return jsonify({
            "ok": True,
            "authorization_url": data["data"]["authorization_url"],
            "access_code": data["data"]["access_code"],
            "reference": data["data"]["reference"],
            "amount_kobo": amount_kobo,
            "currency": currency,
            "plan": plan,
        }), 200

    except ValueError as ve:
        return jsonify({"ok": False, "error": str(ve)}), 400
    except Exception as e:
        log.exception("paystack_initialize error")
        return jsonify({"ok": False, "error": "server_error", "details": str(e)}), 500


# -----------------------------
# PAYSTACK: Webhook
# -----------------------------
@paystack_bp.post("/paystack/webhook")
def paystack_webhook():
    """
    Paystack webhook:
    - Validate signature using SHA512 HMAC with secret
    - Handle charge.success only
    """
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_WEBHOOK_SECRET/PAYSTACK_SECRET_KEY not set", 500

    expected = hmac.new(
        PAYSTACK_WEBHOOK_SECRET.encode("utf-8"),
        raw,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_type = event.get("event")
    data = event.get("data") or {}

    # Always 200 quickly for non-target events
    if event_type != "charge.success":
        return "ok", 200

    try:
        status = (data.get("status") or "").lower()
        if status != "success":
            return "ok", 200

        metadata = data.get("metadata") or {}
        wa_phone = (metadata.get("wa_phone") or "").strip()
        plan = (metadata.get("plan") or "").strip().lower()
        reference = (data.get("reference") or "").strip()

        if not wa_phone or not plan:
            # We cannot activate without wa_phone & plan
            log.warning("Webhook missing wa_phone/plan metadata. reference=%s", reference)
            return "ok", 200

        # Read plan (amount/duration) from DB for correctness
        plan_row = get_plan_from_db(plan)
        duration_days = plan_row["duration_days"]

        # Idempotent/extend-safe activation
        activate_or_extend_subscription(wa_phone=wa_phone, plan=plan, duration_days=duration_days)

        return "ok", 200

    except Exception as e:
        # IMPORTANT: still return 200 to prevent Paystack retries spamming,
        # but log the error so you can see it.
        log.exception("Webhook processing error: %s", e)
        return "ok", 200
