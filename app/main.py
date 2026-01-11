import os
import re
import json
import hmac
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from flask import Flask, request, jsonify
from supabase import create_client

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ------------------------------------------------------------
# ENV
# ------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

# Your public website base URL (must be https in production)
APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip().rstrip("/")

# Optional: if plan.duration_days is null, use this fallback
DEFAULT_PLAN_DURATION_DAYS = int(os.getenv("DEFAULT_PLAN_DURATION_DAYS", "30"))

# CORS allowlist (comma-separated)
FRONTEND_ORIGINS = os.getenv("FRONTEND_ORIGINS", "").strip()

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------
PAYSTACK_INIT_URL = "https://api.paystack.co/transaction/initialize"
PAYSTACK_VERIFY_URL = "https://api.paystack.co/transaction/verify/"

# ------------------------------------------------------------
# Supabase client
# ------------------------------------------------------------
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set. Requests will fail.")
supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def safe_text(v: Any) -> str:
    return str(v or "").strip()

def normalize_wa_phone(wa_phone: str) -> str:
    """
    Normalize to digits only (your DB matching depends on consistent format).
    Example: "+234 815-101-8785" -> "2348151018785"
    """
    s = safe_text(wa_phone)
    s = re.sub(r"\D", "", s)
    return s

def paystack_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

def cors_headers() -> Dict[str, str]:
    """
    Minimal CORS for your Next.js frontend. If FRONTEND_ORIGINS is empty,
    we will not send allow-origin, which is safer.
    """
    origin = request.headers.get("Origin", "")
    allowed = [o.strip() for o in FRONTEND_ORIGINS.split(",") if o.strip()]
    if origin and origin in allowed:
        return {
            "Access-Control-Allow-Origin": origin,
            "Vary": "Origin",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        }
    return {}

@app.after_request
def apply_cors(resp):
    for k, v in cors_headers().items():
        resp.headers[k] = v
    return resp

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "ts": iso(now_utc())})


# ------------------------------------------------------------
# DB helpers
# ------------------------------------------------------------
def get_plan_from_db(plan: str) -> Tuple[int, int, str]:
    """
    Reads public.plans where plan=eq.<plan>
    Must return: amount_kobo, duration_days, currency
    """
    plan = plan.lower().strip()
    res = (
        supabase.table("plans")
        .select("amount_kobo,duration_days,currency")
        .eq("plan", plan)
        .limit(1)
        .execute()
    )
    rows = res.data or []
    if not rows:
        raise ValueError(f"Unknown plan '{plan}'. Check public.plans table.")
    row = rows[0]
    amount_kobo = int(row.get("amount_kobo") or 0)
    duration_days = int(row.get("duration_days") or DEFAULT_PLAN_DURATION_DAYS)
    currency = safe_text(row.get("currency") or "NGN") or "NGN"
    if amount_kobo <= 0:
        raise ValueError("Plan amount_kobo must be > 0 in public.plans.")
    if duration_days <= 0:
        duration_days = DEFAULT_PLAN_DURATION_DAYS
    return amount_kobo, duration_days, currency

def upsert_pending_subscription(
    wa_phone: str,
    email: str,
    plan: str,
    amount_kobo: int,
    currency: str,
    duration_days: int,
    paystack_reference: str,
) -> None:
    """
    Upserts into public.user_subscriptions using columns you showed:
    wa_phone, plan, status, expires_at, paystack_reference, last_event, updated_at,
    amount_kobo, currency, duration_days, email, reference (optional if present)
    """
    payload: Dict[str, Any] = {
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "pending",
        "expires_at": None,
        "paystack_reference": paystack_reference,
        "last_event": "charge.initialize",
        "updated_at": iso(now_utc()),
        "amount_kobo": int(amount_kobo),
        "currency": currency,
        "duration_days": int(duration_days),
        "email": email,
        # Some schemas also have "reference". If yours exists, this helps.
        "reference": paystack_reference,
    }
    supabase.table("user_subscriptions").upsert(payload, on_conflict="wa_phone").execute()

def activate_user_subscription(wa_phone: str, plan: str, duration_days: int) -> None:
    expires_at = iso(now_utc() + timedelta(days=int(duration_days)))
    supabase.table("user_subscriptions").upsert(
        {
            "wa_phone": wa_phone,
            "plan": plan,
            "status": "active",
            "expires_at": expires_at,
            "updated_at": iso(now_utc()),
            "last_event": "charge.success",
        },
        on_conflict="wa_phone",
    ).execute()

def mark_failed_subscription(wa_phone: str, reason: str = "charge.failed") -> None:
    supabase.table("user_subscriptions").update(
        {
            "status": "failed",
            "last_event": reason,
            "updated_at": iso(now_utc()),
        }
    ).eq("wa_phone", wa_phone).execute()

def find_subscription_by_reference(reference: str) -> Optional[Dict[str, Any]]:
    """
    Find row using paystack_reference OR reference (some schemas keep both).
    """
    reference = safe_text(reference)
    if not reference:
        return None

    # Try paystack_reference first
    res = (
        supabase.table("user_subscriptions")
        .select("*")
        .eq("paystack_reference", reference)
        .limit(1)
        .execute()
    )
    rows = res.data or []
    if rows:
        return rows[0]

    # Fallback to reference column (if your schema uses it)
    res2 = (
        supabase.table("user_subscriptions")
        .select("*")
        .eq("reference", reference)
        .limit(1)
        .execute()
    )
    rows2 = res2.data or []
    if rows2:
        return rows2[0]

    return None


# ------------------------------------------------------------
# Paystack endpoints
# ------------------------------------------------------------
@app.route("/paystack/initialize", methods=["POST", "OPTIONS"])
def paystack_initialize():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}
    wa_phone = normalize_wa_phone(data.get("wa_phone"))
    email = safe_text(data.get("email")).lower()
    plan = safe_text(data.get("plan")).lower()

    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    if not APP_BASE_URL:
        return jsonify({"ok": False, "error": "APP_BASE_URL not set"}), 500

    if not wa_phone or not email or not plan:
        return jsonify({"ok": False, "error": "wa_phone, email, plan required"}), 400

    try:
        amount_kobo, duration_days, currency = get_plan_from_db(plan)

        # Use Paystack reference that matches your DB row and webhook
        paystack_reference = f"ntg_{wa_phone}_{int(now_utc().timestamp())}"

        # 1) record pending subscription in Supabase
        upsert_pending_subscription(
            wa_phone=wa_phone,
            email=email,
            plan=plan,
            amount_kobo=amount_kobo,
            currency=currency,
            duration_days=duration_days,
            paystack_reference=paystack_reference,
        )

        # 2) initialize Paystack with callback_url to YOUR success page
        payload = {
            "email": email,
            "amount": amount_kobo,
            "currency": currency,
            "reference": paystack_reference,
            "callback_url": f"{APP_BASE_URL}/payment-success",
            "metadata": {
                "wa_phone": wa_phone,
                "plan": plan,
            },
        }

        r = requests.post(PAYSTACK_INIT_URL, headers=paystack_headers(), json=payload, timeout=30)
        resp = r.json() if r.content else {}

        if r.status_code >= 400 or not resp.get("status"):
            logging.error("Paystack init failed: %s", resp)
            mark_failed_subscription(wa_phone, "initialize.failed")
            return jsonify({"ok": False, "error": "paystack_initialize_failed", "detail": resp}), 502

        auth_url = resp["data"]["authorization_url"]
        ref = resp["data"].get("reference") or paystack_reference

        # Update stored reference if Paystack changes it (rare)
        if ref != paystack_reference:
            supabase.table("user_subscriptions").update(
                {"paystack_reference": ref, "reference": ref, "updated_at": iso(now_utc())}
            ).eq("wa_phone", wa_phone).execute()

        return jsonify({"ok": True, "authorization_url": auth_url, "reference": ref}), 200

    except Exception as e:
        logging.exception("initialize error")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/paystack/verify", methods=["POST", "OPTIONS"])
def paystack_verify():
    """
    Called by frontend success page: verifies transaction and activates subscription.
    """
    if request.method == "OPTIONS":
        return ("", 204)

    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}
    reference = safe_text(data.get("reference"))

    if not reference:
        return jsonify({"ok": False, "error": "reference required"}), 400

    try:
        vr = requests.get(
            f"{PAYSTACK_VERIFY_URL}{reference}",
            headers=paystack_headers(),
            timeout=30,
        )
        payload = vr.json() if vr.content else {}

        if vr.status_code != 200 or not payload.get("status"):
            return jsonify({"ok": False, "error": "verify_failed", "detail": payload}), 502

        v = payload.get("data") or {}
        if v.get("status") != "success":
            return jsonify({"ok": False, "error": f"payment_not_success: {v.get('status')}", "detail": v}), 400

        sub = find_subscription_by_reference(reference)
        if not sub:
            # if metadata contains phone, try using it
            meta = v.get("metadata") or {}
            wa_phone = normalize_wa_phone(meta.get("wa_phone"))
            if wa_phone:
                # attempt load by phone
                res = supabase.table("user_subscriptions").select("*").eq("wa_phone", wa_phone).limit(1).execute()
                rows = res.data or []
                sub = rows[0] if rows else None

        if not sub:
            return jsonify({"ok": False, "error": "subscription_not_found_for_reference"}), 404

        wa_phone = sub["wa_phone"]
        plan = sub.get("plan") or (v.get("metadata") or {}).get("plan") or "monthly"
        duration_days = int(sub.get("duration_days") or DEFAULT_PLAN_DURATION_DAYS)

        activate_user_subscription(wa_phone, plan, duration_days)

        # keep audit
        supabase.table("user_subscriptions").update(
            {"last_event": "verify.success", "updated_at": iso(now_utc())}
        ).eq("wa_phone", wa_phone).execute()

        return jsonify({"ok": True, "wa_phone": wa_phone, "plan": plan, "reference": reference}), 200

    except Exception as e:
        logging.exception("verify error")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/paystack/webhook", methods=["POST"])
def paystack_webhook():
    """
    Paystack sends events here.
    We MUST validate the signature: x-paystack-signature (HMAC SHA512).
    """
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY:
        return "PAYSTACK_SECRET_KEY not set", 500

    expected = hmac.new(PAYSTACK_SECRET_KEY.encode("utf-8"), raw, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    try:
        event = json.loads(raw.decode("utf-8") or "{}")
    except Exception:
        return "invalid json", 400

    event_type = safe_text(event.get("event"))
    data = event.get("data") or {}
    reference = safe_text(data.get("reference"))
    status = safe_text(data.get("status"))

    logging.info("Paystack webhook event=%s reference=%s status=%s", event_type, reference, status)

    # We only activate on successful charge
    if event_type in ("charge.success", "transaction.success") and status == "success":
        sub = find_subscription_by_reference(reference)

        # If not found, attempt metadata wa_phone
        if not sub:
            meta = data.get("metadata") or {}
            wa_phone = normalize_wa_phone(meta.get("wa_phone"))
            if wa_phone:
                res = supabase.table("user_subscriptions").select("*").eq("wa_phone", wa_phone).limit(1).execute()
                rows = res.data or []
                sub = rows[0] if rows else None

        if not sub:
            logging.warning("Webhook success but no subscription found for reference=%s", reference)
            return "ok", 200  # don't retry forever; you can reconcile later

        wa_phone = sub["wa_phone"]
        plan = sub.get("plan") or (data.get("metadata") or {}).get("plan") or "monthly"
        duration_days = int(sub.get("duration_days") or DEFAULT_PLAN_DURATION_DAYS)

        activate_user_subscription(wa_phone, plan, duration_days)

        # Store that we processed webhook
        supabase.table("user_subscriptions").update(
            {
                "last_event": event_type,
                "updated_at": iso(now_utc()),
                "paystack_reference": reference,
                "reference": reference,
            }
        ).eq("wa_phone", wa_phone).execute()

        return "ok", 200

    # Optional: mark failed
    if event_type in ("charge.failed", "transaction.failed"):
        sub = find_subscription_by_reference(reference)
        if sub:
            mark_failed_subscription(sub["wa_phone"], event_type)
        return "ok", 200

    # Ignore other events
    return "ok", 200


# ------------------------------------------------------------
# Entrypoint (local)
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
