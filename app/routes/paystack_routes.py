from flask import Blueprint, request, jsonify
import hmac, hashlib, os, logging
from datetime import timedelta
from app.core.timeutils import now_utc, iso
from app.db.supabase import supabase

bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

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
    plan = metadata.get("plan", "basic")

    if not provider or not provider_user_id:
        logging.error("Paystack webhook missing identity metadata")
        return jsonify(ok=False, error="missing identity metadata"), 400

    # 1️⃣ Resolve account
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

    # 2️⃣ Activate subscription
    expires_at = iso(now_utc() + timedelta(days=30))

    supabase().table("user_subscriptions").upsert({
        "wa_phone": acct_key,
        "plan": plan,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": iso(now_utc())
    }, on_conflict="wa_phone").execute()

    logging.info(f"Subscription activated for {acct_key}")

    return jsonify(ok=True)
