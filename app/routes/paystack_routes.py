# app/routes/paystack_routes.py
import os
import hmac
import hashlib
import logging
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import requests
from flask import Blueprint, request, jsonify

from app.db.supabase import supabase

log = logging.getLogger(__name__)
bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()
PAYSTACK_BASE = "https://api.paystack.co"

FALLBACK_PLAN_DURATIONS_DAYS = {
    "basic": 30,
    "standard": 90,
    "premium": 365,
}

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()

def parse_iso(s: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def get_plan_from_db(plan: str) -> Dict[str, Any]:
    res = (
        supabase()
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

    dur = row.get("duration_days")
    if dur is None:
        dur = FALLBACK_PLAN_DURATIONS_DAYS.get(plan)
    if dur is None:
        raise ValueError(f"duration_days missing for plan '{plan}' and no fallback available")

    row["duration_days"] = int(dur)
    row["amount_kobo"] = int(row["amount_kobo"])
    return row

def resolve_or_create_account(provider: str, provider_user_id: str) -> str:
    """Returns acct_key like 'acct:<uuid>'."""
    res = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    if res.data:
        acct_id = res.data[0]["id"]
    else:
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

def activate_or_extend_subscription(acct_key: str, plan: str, duration_days: int) -> None:
    existing = None
    try:
        r = (
            supabase()
            .table("user_subscriptions")
            .select("wa_phone,plan,status,expires_at")
            .eq("wa_phone", acct_key)
            .maybe_single()
            .execute()
        )
        existing = r.data
    except Exception as e:
        log.warning("Could not read existing subscription: %s", e)

    base_time = now_utc()
    if existing and existing.get("expires_at"):
        exp_dt = parse_iso(existing["expires_at"]) if isinstance(existing["expires_at"], str) else None
        if exp_dt and exp_dt > base_time:
            base_time = exp_dt

    new_expires = base_time + timedelta(days=int(duration_days))

    payload = {
        "wa_phone": acct_key,
        "plan": plan,
        "status": "active",
        "expires_at": iso(new_expires),
        "updated_at": iso(now_utc()),
        "started_at": iso(now_utc()),
    }
    supabase().table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()


@bp.post("/paystack/initialize")
def paystack_initialize():
    """
    Body:
    {
      "provider": "wa" | "tg" | "web",
      "provider_user_id": "...",
      "email": "user@email.com",
      "plan": "basic|standard|premium"
    }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify(ok=False, error="PAYSTACK_SECRET_KEY not set"), 500

    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip()
    provider_user_id = (body.get("provider_user_id") or "").strip()
    email = (body.get("email") or "").strip()
    plan = (body.get("plan") or "").strip().lower()

    if provider not in ("wa", "tg", "web"):
        return jsonify(ok=False, error="provider must be wa|tg|web"), 400
    if not provider_user_id:
        return jsonify(ok=False, error="provider_user_id required"), 400
    if not email:
        return jsonify(ok=False, error="email required"), 400
    if not plan:
        return jsonify(ok=False, error="plan required"), 400

    try:
        plan_row = get_plan_from_db(plan)
    except ValueError as ve:
        return jsonify(ok=False, error=str(ve)), 400

    acct_key = resolve_or_create_account(provider, provider_user_id)
    reference = f"ntg_{uuid4().hex}"

    payload = {
        "email": email,
        "amount": plan_row["amount_kobo"],
        "currency": plan_row.get("currency", "NGN"),
        "reference": reference,
        "metadata": {
            "provider": provider,
            "provider_user_id": provider_user_id,
            "plan": plan,
            "acct_key": acct_key,  # optional debug
            "plan_title": plan_row.get("title") or plan.upper(),
        },
    }
    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    resp = requests.post(
        f"{PAYSTACK_BASE}/transaction/initialize",
        headers={
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=30,
    )

    data = resp.json() if resp.content else {}
    if resp.status_code >= 400 or not data.get("status"):
        return jsonify(ok=False, error="Paystack initialize failed", paystack_status_code=resp.status_code, paystack_response=data), 400

    return jsonify(
        ok=True,
        authorization_url=data["data"]["authorization_url"],
        access_code=data["data"]["access_code"],
        reference=data["data"]["reference"],
        plan=plan,
        amount_kobo=plan_row["amount_kobo"],
        currency=plan_row.get("currency", "NGN"),
    ), 200


@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_WEBHOOK_SECRET:
        return "PAYSTACK_WEBHOOK_SECRET/PAYSTACK_SECRET_KEY not set", 500

    expected = hmac.new(PAYSTACK_WEBHOOK_SECRET.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    event_type = event.get("event")
    data = event.get("data") or {}

    if event_type != "charge.success":
        return "ok", 200

    try:
        status = (data.get("status") or "").lower()
        if status != "success":
            return "ok", 200

        metadata = data.get("metadata") or {}
        provider = (metadata.get("provider") or "").strip()
        provider_user_id = (metadata.get("provider_user_id") or "").strip()
        plan = (metadata.get("plan") or "").strip().lower()

        if not provider or not provider_user_id or not plan:
            log.warning("Webhook missing provider/provider_user_id/plan. ref=%s", data.get("reference"))
            return "ok", 200

        plan_row = get_plan_from_db(plan)
        duration_days = int(plan_row["duration_days"])

        # resolve to acct_key (do not trust acct_key from metadata blindly)
        acct_key = resolve_or_create_account(provider, provider_user_id)

        activate_or_extend_subscription(acct_key=acct_key, plan=plan, duration_days=duration_days)

        log.info("Subscription activated/extended acct_key=%s plan=%s", acct_key, plan)
        return "ok", 200

    except Exception as e:
        log.exception("Webhook processing error: %s", e)
        return "ok", 200
