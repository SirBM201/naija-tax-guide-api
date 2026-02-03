import os
import uuid
import requests
from flask import Blueprint, request, jsonify

paystack_bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

# Price list (kobo)
PLAN_PRICES = {
    "monthly": 300000,    # ₦3,000
    "quarterly": 800000,  # ₦8,000
    "yearly": 3000000,    # ₦30,000
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

    payload = {
        "email": email,
        "amount": PLAN_PRICES[plan_code],
        "reference": reference,
        "callback_url": PAYSTACK_CALLBACK_URL,
        "metadata": {
            "account_id": account_id,
            "plan_code": plan_code,
            "product": "naija-tax-guide",
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
            timeout=15,
        )
        data = resp.json()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if not data.get("status"):
        return jsonify({"error": data}), 400

    return jsonify({
        "authorization_url": data["data"]["authorization_url"],
        "reference": reference,
    })
