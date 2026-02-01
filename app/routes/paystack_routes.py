import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

import requests
from flask import Blueprint, request, jsonify

from app.db.supabase_client import supabase
from app.core.identity import ensure_account, normalize_provider, normalize_provider_user_id, digits_only

log = logging.getLogger(__name__)
bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = (os.getenv("PAYSTACK_SECRET_KEY") or "").strip()
PAYSTACK_WEBHOOK_SECRET = (os.getenv("PAYSTACK_WEBHOOK_SECRET") or PAYSTACK_SECRET_KEY).strip()
PAYSTACK_BASE = "https://api.paystack.co"
PAYSTACK_CALLBACK_URL = (os.getenv("PAYSTACK_CALLBACK_URL") or "").strip()

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

def safe_email_from_identity(provider: str, provider_user_id: str) -> str:
    base = (provider_user_id or "").strip()
    if provider in ("wa", "web"):
        base = digits_only(base) or "0000000000"
    else:
        base = base or "000000"
    return f"user_{provider}_{base}@naija-tax-guide.local"

def get_plan_from_db(plan: str) -> Dict[str, Any]:
    p = (plan or "").strip().lower()
    if p not in ("monthly", "quarterly", "yearly"):
        raise ValueError("invalid plan")

    res = (
        supabase()
        .table("plans")
        .select("plan,title,amount_kobo,currency,duration_days")
        .eq("plan", p)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    if not rows:
        raise ValueError(f"Plan not found in DB: {p}")

    row = rows[0] or {}
    amount_kobo = row.get("amount_kobo")
    if amount_kobo is None:
        raise ValueError(f"Plan '{p}' missing amount_kobo")

    currency = row.get("currency") or "NGN"
    duration_days = row.get("duration_days")
    if duration_days is None:
        duration_days = 30 if p == "monthly" else 90 if p == "quarterly" else 365

    title = row.get("title") or p.title()
    return {
        "plan": p,
        "title": title,
        "amount_kobo": int(amount_kobo),
        "currency": currency,
        "duration_days": int(duration_days),
    }

def activate_or_extend_subscription(acct_key: str, plan: str, duration_days: int, reference: Optional[str]) -> None:
    """
    user_subscriptions.wa_phone stores acct:<uuid>
    """
    base_time = now_utc()

    existing = (
        supabase()
        .table("user_subscriptions")
        .select("expires_at,paystack_reference")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )
    rows = getattr(existing, "data", None) or []
    if rows:
        row = rows[0] or {}
        if reference and row.get("paystack_reference") == reference:
            log.info("Idempotent webhook: already applied %s", reference)
            return
        exp_raw = row.get("expires_at")
        if exp_raw:
            try:
                exp_dt = datetime.fromisoformat(str(exp_raw).replace("Z", "+00:00"))
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
    supabase().table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()

    if reference:
        supabase().table("user_subscriptions").update(
            {"paystack_reference": reference, "updated_at": iso(now_utc())}
        ).eq("wa_phone", acct_key).execute()

@bp.post("/paystack/initialize")
def paystack_initialize():
    if not PAYSTACK_SECRET_KEY:
        return jsonify(ok=False, error="PAYSTACK_SECRET_KEY not set"), 500

    body = request.get_json(silent=True) or {}

    plan = (body.get("plan") or "").strip().lower()
    provider = normalize_provider(body.get("provider") or ("wa" if body.get("wa_phone") else "web"))
    provider_user_id = (body.get("provider_user_id") or "").strip()

    wa_phone = (body.get("wa_phone") or "").strip()
    if wa_phone and not provider_user_id:
        provider_user_id = digits_only(wa_phone)

    provider_user_id = normalize_provider_user_id(provider, provider_user_id)
    if not provider_user_id:
        return jsonify(ok=False, error="provider_user_id required"), 400

    if plan not in ("monthly", "quarterly", "yearly"):
        return jsonify(ok=False, error="plan must be monthly|quarterly|yearly"), 400

    email = (body.get("email") or "").strip()
    if not email:
        email = safe_email_from_identity(provider, provider_user_id)

    try:
        acct_key = ensure_account(provider, provider_user_id)
        plan_row = get_plan_from_db(plan)

        headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
        payload: Dict[str, Any] = {
            "email": email,
            "amount": plan_row["amount_kobo"],
            "currency": plan_row["currency"],
            "metadata": {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "plan": plan,
                "acct_key": acct_key,
                "purpose": "subscription",
            },
        }
        if PAYSTACK_CALLBACK_URL:
            payload["callback_url"] = PAYSTACK_CALLBACK_URL

        r = requests.post(f"{PAYSTACK_BASE}/transaction/initialize", headers=headers, json=payload, timeout=30)
        if not r.ok:
            log.error("Paystack init failed: %s %s", r.status_code, r.text[:500])
            return jsonify(ok=False, error="paystack init failed", details=r.text), 400

        resj = r.json()
        dataj = resj.get("data") or {}
        return jsonify(
            ok=True,
            authorization_url=dataj.get("authorization_url"),
            reference=dataj.get("reference"),
            plan=plan_row["plan"],
            label=plan_row["title"],
            amount_kobo=plan_row["amount_kobo"],
            acct_key=acct_key,
        ), 200

    except Exception as e:
        log.exception("paystack_initialize error")
        return jsonify(ok=False, error="server_error", details=str(e)), 500

@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")
    if not (PAYSTACK_SECRET_KEY or PAYSTACK_WEBHOOK_SECRET):
        return "PAYSTACK_SECRET_KEY not set", 500
    if not verify_paystack_signature(raw, sig):
        return "invalid signature", 401

    event = request.get_json(silent=True) or {}
    if event.get("event") != "charge.success":
        return jsonify(ok=True), 200

    data = event.get("data", {}) or {}
    if (data.get("status") or "").lower() != "success":
        return jsonify(ok=True), 200

    metadata = data.get("metadata", {}) or {}
    provider = normalize_provider(metadata.get("provider") or "")
    provider_user_id = (metadata.get("provider_user_id") or "").strip()
    plan = (metadata.get("plan") or "").strip().lower()
    reference = (data.get("reference") or "").strip() or None

    provider_user_id = normalize_provider_user_id(provider, provider_user_id)
    if provider not in ("wa", "tg", "web") or not provider_user_id or plan not in ("monthly","quarterly","yearly"):
        log.warning("Webhook invalid metadata provider=%s user_id=%s plan=%s", provider, provider_user_id, plan)
        return jsonify(ok=True), 200

    try:
        acct_key = ensure_account(provider, provider_user_id)
        plan_row = get_plan_from_db(plan)
        activate_or_extend_subscription(acct_key, plan, plan_row["duration_days"], reference)
        log.info("Subscription activated %s plan=%s ref=%s", acct_key, plan, reference)
        return jsonify(ok=True), 200
    except Exception:
        log.exception("Webhook processing error")
        return jsonify(ok=True), 200
