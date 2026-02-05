import os
import uuid
import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase

paystack_bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

PLAN_PRICES = {
    "monthly": 300000,
    "quarterly": 800000,
    "yearly": 3000000,
}


@paystack_bp.route("/api/paystack/init", methods=["POST"])
def init_payment():

    if not PAYSTACK_SECRET_KEY:
        return jsonify({"error": "Paystack key not configured"}), 500

    data = request.get_json(silent=True) or {}

    account_id = data.get("account_id")
    email = data.get("email")
    plan_code = data.get("plan_code")

    if not account_id or not email or not plan_code:
        return jsonify({"error": "Missing required fields"}), 400

    if plan_code not in PLAN_PRICES:
        return jsonify({"error": "Invalid plan"}), 400

    reference = f"NTG-{uuid.uuid4()}"
    amount = PLAN_PRICES[plan_code]

    payload = {
        "email": email,
        "amount": amount,
        "reference": reference,
        "callback_url": PAYSTACK_CALLBACK_URL,
        "metadata": {
            "account_id": account_id,
            "plan_code": plan_code,
        },
    }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    resp = requests.post(
        "https://api.paystack.co/transaction/initialize",
        json=payload,
        headers=headers,
        timeout=15,
    )

    pdata = resp.json()

    if not pdata.get("status"):
        return jsonify({"error": pdata}), 400

    # ✅ Save pending transaction
    sb = supabase()
    sb.table("paystack_tx").insert({
        "reference": reference,
        "account_id": account_id,
        "plan_code": plan_code,
        "amount_kobo": amount,
        "status": "pending"
    }).execute()

    return jsonify({
        "authorization_url": pdata["data"]["authorization_url"],
        "reference": reference,
    })
