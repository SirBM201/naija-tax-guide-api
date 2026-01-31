# app/routes/paystack_routes.py
import os
import hmac
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase  # MUST be a function returning supabase client

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


def normalize_digits(s: str) -> str:
    return "".join(ch for ch in (s or "") if ch.isdigit())


def normalize_provider(p: str) -> str:
    v = (p or "").strip().lower()
    if v in ("wa", "whatsapp"):
        return "wa"
    if v in ("tg", "telegram"):
        return "tg"
    return "web"


def safe_email_from_identity(provider: str, provider_user_id: str) -> str:
    """
    Paystack requires email.
    If user didn't supply, generate a safe placeholder that is stable per identity.
    """
    base = provider_user_id.strip()
    if provider in ("wa", "web"):
        base = normalize_digits(base) or "0000000000"
    else:
        base = base or "000000"
    return f"user_{provider}_{base}@naija-tax-guide.local"


def get_plan_from_db(plan: str) -> Dict[str, Any]:
    """
    Reads public.plans.
    Your DB currently has title NOT NULL, so we select it too.

    Expected columns (based on your screenshots):
      - plan (text pk)
      - title (text not null)
      - amount_kobo (int not null)
      - currency (text not null default 'NGN')
      - duration_days (int not null)  (some earlier drafts called it duration_days)
    """
    p = (plan or "").strip().lower()
    if p not in ("monthly", "quarterly", "yearly"):
        raise ValueError("invalid plan")

    res = (
        supabase()
        .table("plans")
        .select("plan,title,amount_kobo,currency,duration_days,duration_days")
        .eq("plan", p)
        .limit(1)
        .execute()
    )

    if not getattr(res, "data", None):
        raise ValueError(f"Plan not found in DB: {p}")

    row = res.data[0] or {}
    amount_kobo = row.get("amount_kobo")
    if amount_kobo is None:
        raise ValueError(f"Plan '{p}' has no amount_kobo")

    currency = row.get("currency") or "NGN"

    # support both duration_days and duration_days (just in case)
    duration_days = row.get("duration_days")
    if duration_days is None:
        duration_days = row.get("duration_days")

    if duration_days is None:
        # fallback safety
        duration_days = 30 if p == "monthly" else 90 if p == "quarterly" else 365

    title = row.get("title") or p.title()

    return {
        "plan": p,
        "title": title,
        "amount_kobo": int(amount_kobo),
        "currency": currency,
        "duration_days": int(duration_days),
    }


def ensure_account(provider: str, provider_user_id: str) -> str:
    """
    Ensure accounts row exists and return acct_key = acct:<uuid>
    accounts schema you showed:
      id uuid pk
      provider text
      provider_user_id text
      created_at timestamptz (likely default now())
    """
    provider = normalize_provider(provider)
    provider_user_id = (provider_user_id or "").strip()
    if not provider_user_id:
        raise ValueError("provider_user_id required")

    # normalize digits for web/wa identities
    if provider in ("wa", "web"):
        provider_user_id = normalize_digits(provider_user_id)

    r = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )

    if getattr(r, "data", None):
        acct_id = r.data[0]["id"]
        return f"acct:{acct_id}"

    ins = (
        supabase()
        .table("accounts")
        .insert(
            {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "phone_e164": None,
            }
        )
        .execute()
    )

    if not getattr(ins, "data", None):
        # race-safe fallback: re-read
        r2 = (
            supabase()
            .table("accounts")
            .select("id")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
        if getattr(r2, "data", None):
            return f"acct:{r2.data[0]['id']}"
        raise RuntimeError("Failed to create account")

    acct_id = ins.data[0]["id"]
    return f"acct:{acct_id}"


def activate_or_extend_subscription(acct_key: str, plan: str, duration_days: int, reference: Optional[str]) -> None:
    """
    Upsert into user_subscriptions using acct_key in wa_phone column.
    Extend from current expiry if still active.

    user_subscriptions schema you showed:
      wa_phone text primary key  (stores acct:<uuid>)
      plan text
      status text
      expires_at timestamptz
      paystack_reference text
      updated_at timestamptz
    """
    base_time = now_utc()

    existing = (
        supabase()
        .table("user_subscriptions")
        .select("expires_at,status,paystack_reference")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )

    if getattr(existing, "data", None):
        row = existing.data[0] or {}

        # idempotency: if same reference already applied, do nothing
        if reference and row.get("paystack_reference") == reference:
            log.info("Subscription already activated for %s ref=%s (idempotent)", acct_key, reference)
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
        # store paystack_reference if column exists
        try:
            supabase().table("user_subscriptions").update(
                {"paystack_reference": reference, "updated_at": iso(now_utc())}
            ).eq("wa_phone", acct_key).execute()
        except Exception:
            pass


# -----------------------------
# POST /paystack/initialize
# -----------------------------
@bp.post("/paystack/initialize")
def paystack_initialize():
    """
    Supports BOTH bodies:

    A) Frontend simple body:
      { "wa_phone": "2348012345678", "plan": "monthly", "email": "x@y.com" }
      -> provider defaults to "wa"
      -> provider_user_id = wa_phone

    B) Full identity body:
      { "provider": "wa|tg|web", "provider_user_id": "...", "plan": "...", "email": "..." }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify(ok=False, error="PAYSTACK_SECRET_KEY not set"), 500

    body = request.get_json(silent=True) or {}

    wa_phone = (body.get("wa_phone") or "").strip()
    plan = (body.get("plan") or "").strip().lower()
    email = (body.get("email") or "").strip()

    provider = normalize_provider(body.get("provider") or ("wa" if wa_phone else "web"))
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if wa_phone and not provider_user_id:
        provider_user_id = normalize_digits(wa_phone)

    # validate
    if provider not in ("wa", "tg", "web"):
        return jsonify(ok=False, error="provider must be wa|tg|web"), 400
    if not provider_user_id:
        return jsonify(ok=False, error="provider_user_id required"), 400
    if plan not in ("monthly", "quarterly", "yearly"):
        return jsonify(ok=False, error="plan must be monthly|quarterly|yearly"), 400

    # email optional: if missing, generate placeholder (stable per identity)
    if not email:
        email = safe_email_from_identity(provider, provider_user_id)

    try:
        acct_key = ensure_account(provider, provider_user_id)
        plan_row = get_plan_from_db(plan)

        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "email": email,
            "amount": plan_row["amount_kobo"],  # already kobo in DB
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

        r = requests.post(
            f"{PAYSTACK_BASE}/transaction/initialize",
            headers=headers,
            json=payload,
            timeout=30,
        )

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
            label=plan_row.get("title") or plan_row["plan"],
            amount_kobo=plan_row["amount_kobo"],
            acct_key=acct_key,
        ), 200

    except Exception as e:
        log.exception("paystack_initialize error")
        return jsonify(ok=False, error="server_error", details=str(e)), 500


# ✅ Alias to stop old frontend paths from breaking
@bp.post("/paystack/subscription/initialize")
def paystack_subscription_initialize_alias():
    return paystack_initialize()


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

    # Only handle successful charges
    if event_type != "charge.success":
        return jsonify(ok=True), 200

    data = event.get("data", {}) or {}
    status = (data.get("status") or "").lower()
    if status != "success":
        return jsonify(ok=True), 200

    metadata = data.get("metadata", {}) or {}
    provider = normalize_provider(metadata.get("provider") or "")
    provider_user_id = (metadata.get("provider_user_id") or "").strip()
    plan = (metadata.get("plan") or "").lower().strip()
    reference = (data.get("reference") or "").strip() or None

    if provider in ("wa", "web"):
        provider_user_id = normalize_digits(provider_user_id)

    if provider not in ("wa", "tg", "web") or not provider_user_id or plan not in ("monthly", "quarterly", "yearly"):
        log.warning(
            "Paystack webhook missing/invalid metadata: provider=%s user_id=%s plan=%s",
            provider,
            provider_user_id,
            plan,
        )
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

        log.info("Subscription activated for %s plan=%s ref=%s", acct_key, plan, reference)
        return jsonify(ok=True), 200

    except Exception as e:
        log.exception("Webhook processing error: %s", e)
        # Return 200 to avoid Paystack retries storm
        return jsonify(ok=True), 200
