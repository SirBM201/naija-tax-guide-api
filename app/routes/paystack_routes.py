from flask import Blueprint, request, jsonify
import hmac, hashlib, os, logging, requests
from datetime import timedelta
from app.core.timeutils import now_utc, iso
from app.db.supabase import supabase

bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_BASE = "https://api.paystack.co"
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

# ---- Plan mapping (adjust amounts to your final pricing) ----
def plan_to_amount_kobo(plan: str) -> int:
    p = (plan or "").strip().lower()
    if p == "monthly":
        return 3000 * 100
    if p == "quarterly":
        return 8000 * 100
    if p == "yearly":
        return 30000 * 100
    raise ValueError("Invalid plan")

def plan_to_duration_days(plan: str) -> int:
    p = (plan or "").strip().lower()
    if p == "monthly":
        return 30
    if p == "quarterly":
        return 90
    if p == "yearly":
        return 365
    raise ValueError("Invalid plan")


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

    data = request.get_json(silent=True) or {}
    provider = (data.get("provider") or "").strip()
    provider_user_id = (data.get("provider_user_id") or "").strip()
    plan = (data.get("plan") or "").strip().lower()
    email = (data.get("email") or "").strip()

    if provider not in ("wa", "tg", "web"):
        return jsonify(ok=False, error="provider must be wa|tg|web"), 400
    if not provider_user_id:
        return jsonify(ok=False, error="provider_user_id required"), 400
    if plan not in ("monthly", "quarterly", "yearly"):
        return jsonify(ok=False, error="plan must be monthly|quarterly|yearly"), 400
    if not email:
        return jsonify(ok=False, error="email required"), 400

    # IMPORTANT: ensure account exists so webhook can resolve it later
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

    acct_key = f"acct:{acct_id}"
    amount_kobo = plan_to_amount_kobo(plan)

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "email": email,
        "amount": amount_kobo,
        "currency": "NGN",
        "callback_url": PAYSTACK_CALLBACK_URL,
        # CRITICAL: identity metadata (acct_key is backend derived; ok to include too, but not required)
        "metadata": {
            "provider": provider,
            "provider_user_id": provider_user_id,
            "plan": plan,
            "acct_key": acct_key,  # optional but helpful for debugging
        },
    }

    r = requests.post(f"{PAYSTACK_BASE}/transaction/initialize", headers=headers, json=payload, timeout=30)
    if not r.ok:
        logging.error(f"Paystack init failed: {r.status_code} {r.text}")
        return jsonify(ok=False, error="paystack init failed", details=r.text), 400

    resj = r.json()
    dataj = resj.get("data") or {}
    return jsonify(
        ok=True,
        authorization_url=dataj.get("authorization_url"),
        reference=dataj.get("reference"),
        acct_key=acct_key,  # optional to show internally
    ), 200


@bp.post("/paystack/webhook")
def paystack_webhook():
    raw = request.get_data() or b""
    sig = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY:
        return "PAYSTACK_SECRET_KEY not set", 500

    expected = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(expected, sig):
        return "invalid signature", 401

    event = request.json or {}
    event_type = event.get("event")

    if event_type != "charge.success":
        return jsonify(ok=True)

    data = event.get("data", {})
    metadata = data.get("metadata", {}) or {}

    provider = metadata.get("provider")
    provider_user_id = metadata.get("provider_user_id")
    plan = (metadata.get("plan") or "monthly").lower()

    if not provider or not provider_user_id:
        logging.error("Paystack webhook missing identity metadata")
        return jsonify(ok=False, error="missing identity metadata"), 400

    # Resolve account -> acct_key
    res = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    if not res.data:
        logging.error("No account found for Paystack metadata")
        return jsonify(ok=False, error="account not found"), 404

    acct_id = res.data[0]["id"]
    acct_key = f"acct:{acct_id}"

    # Activate subscription (duration from plan)
    expires_at = iso(now_utc() + timedelta(days=plan_to_duration_days(plan)))

    supabase().table("user_subscriptions").upsert({
        "wa_phone": acct_key,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

    logging.info(f"Subscription activated for {acct_key} plan={plan}")
    return jsonify(ok=True)
