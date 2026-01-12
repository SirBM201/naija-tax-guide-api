import os
import re
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# -------------------------------------------------
# ENV
# -------------------------------------------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").strip()

DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://thecre8hub.com",
    "https://www.thecre8hub.com",
]

PLAN_DAYS = {
    "monthly": 30,
    "quarterly": 90,
    "yearly": 365,
}

def parse_origins(value: str):
    if not value:
        return DEFAULT_ORIGINS
    return [v.strip() for v in value.split(",") if v.strip()]

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def normalize_wa_phone(s: str) -> str:
    # store digits only, no "+"
    return re.sub(r"\D", "", (s or "").strip())

# -------------------------------------------------
# APP
# -------------------------------------------------
app = Flask(__name__)

CORS(
    app,
    resources={r"/*": {"origins": parse_origins(CORS_ORIGINS)}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=86400,
)

# Supabase client (server-side write)
sb = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def activate_user_subscription(wa_phone: str, plan: str) -> None:
    """
    Upsert into user_subscriptions.
    Requires unique constraint on wa_phone.
    """
    if not sb:
        raise RuntimeError("Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)")

    plan = (plan or "").lower().strip()
    days = PLAN_DAYS.get(plan, 30)

    expires_at = iso(now_utc() + timedelta(days=days))

    sb.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Body:
    {
      "email": "user@email.com",
      "amount": 3000,
      "wa_phone": "234xxxxxxxxxx",
      "plan": "monthly|quarterly|yearly",
      "callback_url": "https://yourdomain.com/payment-success"
    }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip()
    wa_phone = normalize_wa_phone(str(data.get("wa_phone", "")))
    plan = str(data.get("plan", "")).strip().lower()
    callback_url = str(data.get("callback_url", "")).strip()

    amount = data.get("amount")
    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "valid_email_required"}), 400
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone_required"}), 400
    if plan not in ("monthly", "quarterly", "yearly"):
        return jsonify({"ok": False, "error": "invalid_plan"}), 400
    if not amount:
        return jsonify({"ok": False, "error": "amount_required"}), 400

    try:
        amount_kobo = int(float(amount) * 100)
    except Exception:
        return jsonify({"ok": False, "error": "invalid_amount"}), 400

    payload = {
        "email": email,
        "amount": amount_kobo,
        "currency": "NGN",
        "callback_url": callback_url,
        # ✅ Critical: metadata so verify can activate subscription
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
        },
    }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers=headers,
            timeout=30,
        )
        result = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    if resp.status_code != 200 or result.get("status") is not True:
        return jsonify({"ok": False, "error": "paystack_initialize_failed", "detail": result}), 400

    d = result.get("data", {}) or {}
    return jsonify({
        "ok": True,
        "authorization_url": d.get("authorization_url"),
        "access_code": d.get("access_code"),
        "reference": d.get("reference"),
    }), 200

@app.post("/paystack/verify")
def paystack_verify():
    """
    Body: { "reference": "xxxx" }

    If payment is success:
      - reads metadata.wa_phone + metadata.plan
      - upserts into user_subscriptions
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}
    reference = str(data.get("reference", "")).strip()
    if not reference:
        return jsonify({"ok": False, "error": "reference_required"}), 400

    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        payload = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    if resp.status_code != 200:
        return jsonify({"ok": False, "error": "paystack_http_error", "detail": payload}), 502

    if payload.get("status") is not True:
        return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": payload}), 400

    d = payload.get("data") or {}
    paystack_status = str(d.get("status", "")).lower()
    paid = (paystack_status == "success")

    # amount in kobo
    amount_kobo = d.get("amount")
    amount = amount_kobo / 100 if isinstance(amount_kobo, (int, float)) else None

    customer = d.get("customer") or {}
    customer_email = customer.get("email")

    # ✅ Subscription activation on success
    activated = False
    activation_error = None

    if paid:
        try:
            md = d.get("metadata") or {}
            wa_phone = normalize_wa_phone(str(md.get("wa_phone", "")))
            plan = str(md.get("plan", "")).strip().lower()

            if wa_phone and plan:
                activate_user_subscription(wa_phone, plan)
                activated = True
            else:
                activation_error = "missing_metadata_wa_phone_or_plan"
        except Exception as e:
            activation_error = str(e)

    return jsonify({
        "ok": True,
        "paid": paid,
        "reference": reference,
        "status": paystack_status,
        "amount": amount,
        "currency": d.get("currency"),
        "customer_email": customer_email,
        "activated": activated,
        "activation_error": activation_error,
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
import os
import re
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client

# -------------------------------------------------
# ENV
# -------------------------------------------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").strip()

DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://thecre8hub.com",
    "https://www.thecre8hub.com",
]

PLAN_DAYS = {
    "monthly": 30,
    "quarterly": 90,
    "yearly": 365,
}

def parse_origins(value: str):
    if not value:
        return DEFAULT_ORIGINS
    return [v.strip() for v in value.split(",") if v.strip()]

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()

def normalize_wa_phone(s: str) -> str:
    # store digits only, no "+"
    return re.sub(r"\D", "", (s or "").strip())

# -------------------------------------------------
# APP
# -------------------------------------------------
app = Flask(__name__)

CORS(
    app,
    resources={r"/*": {"origins": parse_origins(CORS_ORIGINS)}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=86400,
)

# Supabase client (server-side write)
sb = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def activate_user_subscription(wa_phone: str, plan: str) -> None:
    """
    Upsert into user_subscriptions.
    Requires unique constraint on wa_phone.
    """
    if not sb:
        raise RuntimeError("Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)")

    plan = (plan or "").lower().strip()
    days = PLAN_DAYS.get(plan, 30)

    expires_at = iso(now_utc() + timedelta(days=days))

    sb.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.post("/paystack/initialize")
def paystack_initialize():
    """
    Body:
    {
      "email": "user@email.com",
      "amount": 3000,
      "wa_phone": "234xxxxxxxxxx",
      "plan": "monthly|quarterly|yearly",
      "callback_url": "https://yourdomain.com/payment-success"
    }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip()
    wa_phone = normalize_wa_phone(str(data.get("wa_phone", "")))
    plan = str(data.get("plan", "")).strip().lower()
    callback_url = str(data.get("callback_url", "")).strip()

    amount = data.get("amount")
    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "valid_email_required"}), 400
    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone_required"}), 400
    if plan not in ("monthly", "quarterly", "yearly"):
        return jsonify({"ok": False, "error": "invalid_plan"}), 400
    if not amount:
        return jsonify({"ok": False, "error": "amount_required"}), 400

    try:
        amount_kobo = int(float(amount) * 100)
    except Exception:
        return jsonify({"ok": False, "error": "invalid_amount"}), 400

    payload = {
        "email": email,
        "amount": amount_kobo,
        "currency": "NGN",
        "callback_url": callback_url,
        # ✅ Critical: metadata so verify can activate subscription
        "metadata": {
            "wa_phone": wa_phone,
            "plan": plan,
            "purpose": "subscription",
        },
    }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers=headers,
            timeout=30,
        )
        result = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    if resp.status_code != 200 or result.get("status") is not True:
        return jsonify({"ok": False, "error": "paystack_initialize_failed", "detail": result}), 400

    d = result.get("data", {}) or {}
    return jsonify({
        "ok": True,
        "authorization_url": d.get("authorization_url"),
        "access_code": d.get("access_code"),
        "reference": d.get("reference"),
    }), 200

@app.post("/paystack/verify")
def paystack_verify():
    """
    Body: { "reference": "xxxx" }

    If payment is success:
      - reads metadata.wa_phone + metadata.plan
      - upserts into user_subscriptions
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}
    reference = str(data.get("reference", "")).strip()
    if not reference:
        return jsonify({"ok": False, "error": "reference_required"}), 400

    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        payload = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    if resp.status_code != 200:
        return jsonify({"ok": False, "error": "paystack_http_error", "detail": payload}), 502

    if payload.get("status") is not True:
        return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": payload}), 400

    d = payload.get("data") or {}
    paystack_status = str(d.get("status", "")).lower()
    paid = (paystack_status == "success")

    # amount in kobo
    amount_kobo = d.get("amount")
    amount = amount_kobo / 100 if isinstance(amount_kobo, (int, float)) else None

    customer = d.get("customer") or {}
    customer_email = customer.get("email")

    # ✅ Subscription activation on success
    activated = False
    activation_error = None

    if paid:
        try:
            md = d.get("metadata") or {}
            wa_phone = normalize_wa_phone(str(md.get("wa_phone", "")))
            plan = str(md.get("plan", "")).strip().lower()

            if wa_phone and plan:
                activate_user_subscription(wa_phone, plan)
                activated = True
            else:
                activation_error = "missing_metadata_wa_phone_or_plan"
        except Exception as e:
            activation_error = str(e)

    return jsonify({
        "ok": True,
        "paid": paid,
        "reference": reference,
        "status": paystack_status,
        "amount": amount,
        "currency": d.get("currency"),
        "customer_email": customer_email,
        "activated": activated,
        "activation_error": activation_error,
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
