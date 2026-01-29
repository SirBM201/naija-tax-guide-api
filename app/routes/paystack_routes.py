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

from app.db.supabase_client import supabase  # FUNCTION -> supabase().table(...)

bp = Blueprint("paystack", __name__)

# -----------------------------
# ENV
# -----------------------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_WEBHOOK_SECRET = os.getenv("PAYSTACK_WEBHOOK_SECRET", PAYSTACK_SECRET_KEY).strip()

FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip()

# -----------------------------
# Plans (NEW PRICES)
# -----------------------------
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

def _digits(x: str) -> str:
    return "".join(ch for ch in (x or "").strip() if ch.isdigit())

def _normalize_provider(p: str) -> str:
    v = (p or "").strip().lower()
    if v in ("wa", "whatsapp"):
        return "wa"
    if v in ("tg", "telegram"):
        return "tg"
    return "web"

def _acct_key(acct_id: str) -> str:
    return f"acct:{acct_id}"

def _resolve_acct_id(provider: str, provider_user_id: str, phone_e164: Optional[str] = None) -> str:
    """
    Accounts table only (no Supabase Auth).
    Unique key: (provider, provider_user_id)
    Returns acct_id (uuid string).
    """
    provider = _normalize_provider(provider)
    provider_user_id = (provider_user_id or "").strip()
    if not provider_user_id:
        raise ValueError("provider_user_id is required")

    # 1) lookup
    r = (
        supabase()
        .table("accounts")
        .select("acct_id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return str(rows[0]["acct_id"])

    # 2) create
    payload = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "status": "active",
        "updated_at": _now_iso(),
    }
    if phone_e164:
        payload["phone_e164"] = (phone_e164 or "")[:40]

    ins = supabase().table("accounts").insert(payload).execute()
    created = getattr(ins, "data", None) or []
    if created and created[0].get("acct_id"):
        return str(created[0]["acct_id"])

    # 3) retry read
    r2 = (
        supabase()
        .table("accounts")
        .select("acct_id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows2 = getattr(r2, "data", None) or []
    if rows2:
        return str(rows2[0]["acct_id"])

    raise RuntimeError("Failed to resolve acct_id")

def _get_plan(plan: str) -> Optional[Dict[str, Any]]:
    if not plan:
        return None
    return PLANS.get(plan.strip().lower())

def _get_topup_package(code: str) -> Optional[Dict[str, Any]]:
    if not code:
        return None
    return TOPUP_PACKAGES.get(code.strip().upper())

def _frontend_url(path: str, params: Optional[Dict[str, Any]] = None) -> str:
    base = (FRONTEND_BASE_URL or "").rstrip("/")
    if not base:
        return ""
    p = "/" + path.lstrip("/")
    if params:
        return f"{base}{p}?{urlencode(params)}"
    return f"{base}{p}"

def _get_subscription(acct_key_value: str) -> Optional[Dict[str, Any]]:
    """
    Option 2: user_subscriptions.wa_phone stores acct:<uuid>
    """
    try:
        r = supabase().table("user_subscriptions").select("*").eq("wa_phone", acct_key_value).limit(1).execute()
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
# SUBSCRIPTION: Initialize (Option 2)
# -----------------------------
@bp.post("/paystack/subscription/initialize")
def paystack_subscription_initialize():
    """
    Recommended JSON (Option 2):
      {
        "provider": "web" | "wa" | "tg",
        "provider_user_id": "...",
        "email": "user@example.com",
        "plan": "monthly" | "quarterly" | "yearly",
        "phone_e164": "234..."  (optional)
      }

    Backward compatible:
      { "phone": "234...", "email": "...", "plan": "monthly" }
      -> treated as provider="web", provider_user_id=digits(phone)
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}

    provider = (body.get("provider") or "").strip()
    provider_user_id = (body.get("provider_user_id") or "").strip()
    phone_e164 = _digits(body.get("phone_e164") or "")

    # Old fallback
    old_phone = _digits(body.get("phone") or body.get("wa_phone") or "")
    if not provider_user_id and old_phone:
        provider = "web"
        provider_user_id = old_phone
        if not phone_e164:
            phone_e164 = old_phone

    email = (body.get("email") or "").strip()
    plan = (body.get("plan") or "").strip().lower()

    if not provider_user_id:
        return jsonify({"ok": False, "message": "provider_user_id (or phone) is required"}), 400
    if not email or "@" not in email:
        return jsonify({"ok": False, "message": "Valid email is required"}), 400

    p = _get_plan(plan)
    if not p:
        return jsonify({"ok": False, "message": "Invalid plan"}), 400

    # Resolve acct_key
    acct_id = _resolve_acct_id(provider or "web", provider_user_id, phone_e164=phone_e164 or None)
    acct_key_value = _acct_key(acct_id)

    amount_kobo = int(p["amount_kobo"])
    duration_days = int(p["duration_days"])
    reference = f"sub_{plan}_{int(_now().timestamp())}_{acct_id[:8]}"

    # Save pending subscription (Option 2 key)
    try:
        supabase().table("user_subscriptions").upsert(
            {
                "wa_phone": acct_key_value,
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

    callback_url = _frontend_url("/subscription")
    if not callback_url:
        callback_url = (APP_BASE_URL.rstrip("/") + "/paystack/subscription/callback") if APP_BASE_URL else ""

    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "callback_url": callback_url or None,
        "metadata": {
            "purpose": "subscription",
            "acct_key": acct_key_value,                 # ✅ KEY
            "provider": _normalize_provider(provider),  # helpful for debugging
            "provider_user_id": provider_user_id,
            "duration_days": duration_days,
            "plan": plan,
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
            logging.error("Paystack initialize failed: %s %s", r.status_code, r.text[:500])
            return jsonify({"ok": False, "message": "Paystack initialize failed"}), 502

        resp = r.json() or {}
        if not resp.get("status"):
            logging.error("Paystack initialize status=false: %s", str(resp)[:500])
            return jsonify({"ok": False, "message": "Paystack initialize failed"}), 502

        d = resp.get("data") or {}
        return jsonify(
            {
                "ok": True,
                "authorization_url": d.get("authorization_url"),
                "reference": d.get("reference") or reference,
                "acct_key": acct_key_value,
                "acct_id": acct_id,
            }
        ), 200

    except Exception as e:
        logging.exception("Paystack initialize exception: %s", e)
        return jsonify({"ok": False, "message": "Paystack initialize exception"}), 500


@bp.get("/paystack/subscription/callback")
def paystack_subscription_callback():
    trxref = (request.args.get("trxref") or "").strip()
    reference = (request.args.get("reference") or "").strip()

    url = _frontend_url("/subscription", {"trxref": trxref, "reference": reference})
    if url:
        return redirect(url, code=302)

    return jsonify({"ok": True, "message": "Payment received. Return to the app to refresh status."}), 200


# -----------------------------
# SUBSCRIPTION: Verify (Option 2)
# -----------------------------
@bp.post("/paystack/subscription/verify")
def paystack_subscription_verify():
    """
    Request JSON:
      { "reference": "...", "acct_key": "acct:<uuid>" }  OR
      { "reference": "...", "provider": "...", "provider_user_id": "..." }

    Response:
      { ok: true, status, plan, expires_at, reference, acct_key }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    reference = (body.get("reference") or body.get("paystack_reference") or body.get("trxref") or "").strip()

    if not reference:
        return jsonify({"ok": False, "message": "reference is required"}), 400

    try:
        vr = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers=_headers(),
            timeout=30,
        )
        if vr.status_code != 200:
            logging.error("Paystack verify failed: %s %s", vr.status_code, vr.text[:500])
            return jsonify({"ok": False, "message": "Paystack verify failed"}), 502

        payload = vr.json() or {}
        if not payload.get("status"):
            return jsonify({"ok": False, "message": "Paystack verify returned status=false"}), 502

        data = payload.get("data") or {}
        paid_status = (data.get("status") or "").lower()
        if paid_status not in ("success", "successful"):
            return jsonify({"ok": False, "message": f"Payment not successful (status={paid_status})"}), 400

        md = data.get("metadata") or {}
        purpose = (md.get("purpose") or "").strip().lower()

        if purpose and purpose != "subscription":
            return jsonify({"ok": False, "message": "Not a subscription payment"}), 400

        # ✅ Prefer acct_key from Paystack metadata
        acct_key_value = (md.get("acct_key") or "").strip()

        # fallback: resolve from provider info
        if not acct_key_value:
            provider = (md.get("provider") or body.get("provider") or "web").strip()
            provider_user_id = (md.get("provider_user_id") or body.get("provider_user_id") or "").strip()
            if provider_user_id:
                acct_id = _resolve_acct_id(provider, provider_user_id)
                acct_key_value = _acct_key(acct_id)

        if not acct_key_value:
            return jsonify({"ok": False, "message": "Missing acct_key (or provider/provider_user_id)"}), 400

        md_plan = (md.get("plan") or "").strip().lower()
        md_days = _int(md.get("duration_days"), 0)

        p = _get_plan(md_plan) if md_plan else None
        if not p:
            # fallback to stored plan
            row = _get_subscription(acct_key_value)
            stored_plan = (row.get("plan") if row else "") or "monthly"
            p = _get_plan(stored_plan) or _get_plan("monthly")
            md_plan = stored_plan

        duration_days = md_days or int((p or {}).get("duration_days") or 30)
        expires_at = (_now() + timedelta(days=duration_days)).isoformat()

        supabase().table("user_subscriptions").upsert(
            {
                "wa_phone": acct_key_value,
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
            {"ok": True, "status": "active", "plan": md_plan, "expires_at": expires_at, "reference": reference, "acct_key": acct_key_value}
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
# TOP-UP: Initialize (Option 2; PAID-ONLY)
# -----------------------------
@bp.post("/paystack/topup/initialize")
def paystack_topup_initialize():
    """
    Preferred:
      { "acct_key": "acct:<uuid>", "email": "...", "package_code": "TOPUP_100" }
    Or:
      { "provider":"wa|tg|web", "provider_user_id":"...", "email":"...", "package_code":"TOPUP_100" }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "message": "PAYSTACK_SECRET_KEY not set"}), 500

    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip()
    package_code = (body.get("package_code") or "").strip().upper()

    if not email or "@" not in email:
        return jsonify({"ok": False, "message": "Valid email is required"}), 400

    acct_key_value = (body.get("acct_key") or "").strip()

    if not acct_key_value:
        provider = (body.get("provider") or "web").strip()
        provider_user_id = (body.get("provider_user_id") or "").strip()

        # old fallback
        if not provider_user_id:
            old_phone = _digits(body.get("phone") or body.get("wa_phone") or "")
            if old_phone:
                provider = "web"
                provider_user_id = old_phone

        if not provider_user_id:
            return jsonify({"ok": False, "message": "acct_key OR provider+provider_user_id is required"}), 400

        acct_id = _resolve_acct_id(provider, provider_user_id)
        acct_key_value = _acct_key(acct_id)

    # PAID-ONLY GUARD
    sub = _get_subscription(acct_key_value)
    if not _is_active_paid_subscription(sub):
        return jsonify(
            {"ok": False, "message": "Top-up is only available to active subscribers. Please upgrade first.", "action": "upgrade", "reason": "not_subscribed_or_expired"}
        ), 403

    pkg = _get_topup_package(package_code)
    if not pkg:
        return jsonify({"ok": False, "message": "Invalid package_code"}), 400

    credits = int(pkg["credits"])
    amount_kobo = int(pkg["amount_kobo"])
    reference = f"topup_{acct_key_value.replace(':','_')}_{package_code}_{int(_now().timestamp())}"

    # store pending order first
    try:
        supabase().table("ai_topup_orders").upsert(
            {
                "reference": reference,
                "wa_phone": acct_key_value,   # ✅ store acct_key here too
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

    callback_url = _frontend_url("/subscription")
    if not callback_url:
        callback_url = (APP_BASE_URL.rstrip("/") + "/paystack/topup/callback") if APP_BASE_URL else ""

    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "callback_url": callback_url or None,
        "metadata": {
            "purpose": "ai_topup",
            "acct_key": acct_key_value,  # ✅ KEY
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
            logging.error("Paystack initialize failed: %s %s", r.status_code, r.text[:500])
            return jsonify({"ok": False, "message": "Paystack initialize failed"}), 502

        resp = r.json() or {}
        if not resp.get("status"):
            logging.error("Paystack initialize status false: %s", str(resp)[:500])
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
                "acct_key": acct_key_value,
            }
        ), 200

    except Exception as e:
        logging.exception("Paystack initialize exception: %s", e)
        return jsonify({"ok": False, "message": "Paystack initialize exception"}), 500


@bp.get("/paystack/topup/callback")
def paystack_topup_callback():
    trxref = (request.args.get("trxref") or "").strip()
    reference = (request.args.get("reference") or "").strip()

    url = _frontend_url("/subscription", {"trxref": trxref, "reference": reference})
    if url:
        return redirect(url, code=302)

    return jsonify({"ok": True, "message": "Top-up received. You can return to the app."}), 200


# -----------------------------
# PAYSTACK WEBHOOK (SUBSCRIPTION + TOPUP) - Option 2
# -----------------------------
def _handle_paystack_webhook():
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
    md = data.get("metadata") or {}
    purpose = (md.get("purpose") or "").strip().lower()
    reference = (data.get("reference") or "").strip()

    logging.info("Paystack webhook event=%s purpose=%s ref=%s", event_type, purpose, reference)

    if purpose == "ai_topup":
        return _handle_topup(event_type, data, event)

    if purpose == "subscription":
        return _handle_subscription_webhook(event_type, data, event)

    return jsonify({"ok": True}), 200


@bp.post("/paystack/webhook")
def paystack_webhook():
    return _handle_paystack_webhook()

@bp.post("/webhooks/paystack")
def paystack_webhook_alias():
    return _handle_paystack_webhook()


def _handle_subscription_webhook(event_type: str, data: Dict[str, Any], full_event: Dict[str, Any]):
    if event_type not in ("charge.success", "transaction.success"):
        return jsonify({"ok": True}), 200

    status = (data.get("status") or "").lower()
    if status and status not in ("success", "successful"):
        return jsonify({"ok": True}), 200

    reference = (data.get("reference") or "").strip()
    md = data.get("metadata") or {}

    acct_key_value = (md.get("acct_key") or "").strip()
    plan = (md.get("plan") or "").strip().lower()
    duration_days = _int(md.get("duration_days"), 0)

    # fallback: resolve if acct_key not present
    if not acct_key_value:
        provider = (md.get("provider") or "web").strip()
        provider_user_id = (md.get("provider_user_id") or "").strip()
        if provider_user_id:
            acct_id = _resolve_acct_id(provider, provider_user_id)
            acct_key_value = _acct_key(acct_id)

    if not acct_key_value:
        logging.warning("Subscription webhook missing acct_key ref=%r", reference)
        return jsonify({"ok": True}), 200

    p = _get_plan(plan) or _get_plan("monthly")
    duration_days = duration_days or int(p["duration_days"])
    expires_at = (_now() + timedelta(days=duration_days)).isoformat()

    supabase().table("user_subscriptions").upsert(
        {
            "wa_phone": acct_key_value,  # ✅ acct_key
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
    md = data.get("metadata") or {}

    acct_key_value = (md.get("acct_key") or "").strip()
    credits = _int(md.get("credits"))
    package_code = (md.get("package_code") or "").strip().upper()
    amount_kobo = _int(data.get("amount"))
    email = (data.get("customer") or {}).get("email") or ""

    if not reference or not acct_key_value or credits <= 0 or not package_code:
        logging.warning("Topup missing metadata ref=%r acct_key=%r credits=%r package=%r", reference, acct_key_value, credits, package_code)
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
        supabase().table("ai_topup_orders").upsert(
            {
                "reference": reference,
                "wa_phone": acct_key_value,  # ✅ acct_key
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

    # credit ledger
    try:
        supabase().table("ai_credit_ledger").insert(
            {"wa_phone": acct_key_value, "reference": reference, "credits": credits, "created_at": _now_iso()}
        ).execute()
    except Exception:
        pass

    return jsonify({"ok": True}), 200
