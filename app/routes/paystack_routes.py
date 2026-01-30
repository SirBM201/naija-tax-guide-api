# app/routes/paystack_routes.py
import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase  # ✅ this should exist in your repo

log = logging.getLogger(__name__)

bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()
PAYSTACK_BASE = "https://api.paystack.co"
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

# -----------------------------
# Helpers
# -----------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()

def verify_paystack_signature(raw: bytes, sig: str) -> bool:
    secret = PAYSTACK_WEBHOOK_SECRET or PAYSTACK_SECRET_KEY
    if not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, sig or "")

def get_plan_from_db(plan: str) -> Dict[str, Any]:
    """
    Reads public.plans:
      - plan (text)  e.g. monthly/quarterly/yearly
      - amount_kobo (int)
      - currency (text) default NGN
      - duration_days (int) optional (we fallback if missing)
    """
    p = (plan or "").strip().lower()

    res = (
        supabase()
        .table("plans")
        .select("plan,amount_kobo,currency,duration_days")
        .eq("plan", p)
        .limit(1)
        .execute()
    )
    if not res.data:
        raise ValueError(f"Plan not found in DB: {p}")

    row = res.data[0]
    amount_kobo = row.get("amount_kobo")
    if amount_kobo is None:
        raise ValueError(f"Plan '{p}' has no amount_kobo")

    currency = row.get("currency") or "NGN"

    duration_days = row.get("duration_days")
    if duration_days is None:
        # fallback if you didn't add duration_days yet
        if p == "monthly":
            duration_days = 30
        elif p == "quarterly":
            duration_days = 90
        elif p == "yearly":
            duration_days = 365
        else:
            duration_days = 30

    return {
        "plan": p,
        "amount_kobo": int(amount_kobo),
        "currency": currency,
        "duration_days": int(duration_days),
    }

def ensure_account(provider: str, provider_user_id: str) -> str:
    """
    Ensure accounts row exists and return acct_key = acct:<uuid>
    """
    r = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    if r.data:
        acct_id = r.data[0]["id"]
        return f"acct:{acct_id}"

    ins = (
        supabase()
        .table("accounts")
        .insert({
            "provider": provider,
            "provider_user_id": provider_user_id,
            "phone_e164": None,
        })
        .execute()
    )
    acct_id = ins.data[0]["id"]
    return f"acct:{acct_id}"

def activate_or_extend_subscription(acct_key: str, plan: str, duration_days: int, reference: str | None) -> None:
    """
    Upsert into user_subscriptions using acct_key in wa_phone column.
    Extend from current expiry if still active.
    """
    base_time = now_utc()

    existing = (
        supabase()
        .table("user_subscriptions")
        .select("expires_at,status")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )

    if existing.data:
        exp_raw = existing.data[0].get("expires_at")
        if exp_raw:
            try:
                exp_dt = datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
                if exp_dt > base_time:
                    base_time = exp_dt
            except Exception:
                pass

    expires_at = base_time + timedelta(days=int(duration_days))

    payload = {
        "wa_phone": acct_key,
        "plan": plan,
        "status": "active",
        "expires_at": iso(expires_at),
        "updated_at": iso(now_utc()),
    }

    # if you have these columns, they will store; if not, Supabase ignores unknown fields only if using RPC.
    # So keep it minimal and safe:
    supabase().table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()

    # optional: store reference if you have paystack_reference column
    if reference:
        try:
            supabase().table("user_subscriptions").update({
                "paystack_reference": reference
            }).eq("wa_phone", acct_key).execute()
        except Exception:
            pass


# -----------------------------
# POST /paystack/initialize
# -----------------------------
@bp.post("/paystack/initialize")
def paystack_initialize():
    """
    Body:
    {
      "provider": "wa" | "tg" | "web",
      "provider_user_id": "9656..." | "telegram_id" | "web_user_id",
      "plan": "monthly|quarterly|yearly",
      "email": "customer@email.com"
    }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify(ok=False, error="PAYSTACK_SECRET_KEY not set"), 500

    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip()
    provider_user_id = (body.get("provider_user_id") or "").strip()
    plan = (body.get("plan") or "").strip().lower()
    email = (body.get("email") or "").strip()

    if provider not in ("wa", "tg", "web"):
        return jsonify(ok=False, error="provider must be wa|tg|web"), 400
    if not provider_user_id:
        return jsonify(ok=False, error="provider_user_id required"), 400
    if plan not in ("monthly", "quarterly", "yearly"):
        return jsonify(ok=False, error="plan must be monthly|quarterly|yearly"), 400
    if not email:
        return jsonify(ok=False, error="email required"), 400

    try:
        acct_key = ensure_account(provider, provider_user_id)
        plan_row = get_plan_from_db(plan)

        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        payload = {
            "email": email,
            "amount": plan_row["amount_kobo"],   # already kobo in DB
            "currency": plan_row["currency"],
            "callback_url": PAYSTACK_CALLBACK_URL if PAYSTACK_CALLBACK_URL else None,
            "metadata": {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "plan": plan,
                "acct_key": acct_key,  # helpful for debugging
            },
        }
        # remove callback_url if empty
        if not payload.get("callback_url"):
            payload.pop("callback_url", None)

        r = requests.post(f"{PAYSTACK_BASE}/transaction/initialize", headers=headers, json=payload, timeout=30)
        if not r.ok:
            log.error("Paystack init failed: %s %s", r.status_code, r.text)
            return jsonify(ok=False, error="paystack init failed", details=r.text), 400

        resj = r.json()
        dataj = resj.get("data") or {}
        return jsonify(
            ok=True,
            authorization_url=dataj.get("authorization_url"),
            reference=dataj.get("reference"),
            acct_key=acct_key,
        ), 200

    except Exception as e:
        log.exception("paystack_initialize error")
        return jsonify(ok=False, error="server_error", details=str(e)), 500


# -----------------------------
# POST /paystack/webhook
# -----------------------------
@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not (PAYSTACK_SECRET_KEY or PAYSTACK_WEBHOOK_SECRET):
        return "PAYSTACK_SECRET_KEY not set", 500

    if not verify_paystack_signature(raw, sig):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_type = event.get("event")

    # only handle successful charges
    if event_type != "charge.success":
        return jsonify(ok=True), 200

    data = event.get("data", {}) or {}
    status = (data.get("status") or "").lower()
    if status != "success":
        return jsonify(ok=True), 200

    metadata = data.get("metadata", {}) or {}
    provider = metadata.get("provider")
    provider_user_id = metadata.get("provider_user_id")
    plan = (metadata.get("plan") or "").lower()
    reference = (data.get("reference") or "").strip() or None

    if not provider or not provider_user_id or plan not in ("monthly", "quarterly", "yearly"):
        log.warning("Paystack webhook missing/invalid metadata: provider=%s user_id=%s plan=%s", provider, provider_user_id, plan)
        return jsonify(ok=True), 200

    try:
        acct_key = ensure_account(provider, provider_user_id)
        plan_row = get_plan_from_db(plan)

        activate_or_extend_subscription(
            acct_key=acct_key,
            plan=plan,
            duration_days=plan_row["duration_days"],
            reference=reference,
        )

        log.info("Subscription activated for %s plan=%s", acct_key, plan)
        return jsonify(ok=True), 200

    except Exception as e:
        # Return 200 to avoid Paystack retries storm, but log it.
        log.exception("Webhook processing error: %s", e)
        return jsonify(ok=True), 200
