import os
import requests
from flask import Blueprint, request, jsonify

paystack_bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "")

@paystack_bp.route("/paystack/verify", methods=["POST"])
def verify_paystack_payment():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({
            "status": "error",
            "message": "PAYSTACK_SECRET_KEY not set"
        }), 500

    data = request.get_json(silent=True) or {}
    reference = data.get("reference")

    if not reference:
        return jsonify({
            "status": "error",
            "message": "reference is required"
        }), 400

    try:
        url = f"https://api.paystack.co/transaction/verify/{reference}"
        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        resp = requests.get(url, headers=headers, timeout=20)
        result = resp.json()

        if not result.get("status"):
            return jsonify({
                "status": "failed",
                "message": result.get("message", "Verification failed")
            }), 400

        data = result["data"]

        return jsonify({
            "status": "success",
            "reference": reference,
            "amount": data["amount"] // 100,
            "currency": data["currency"],
            "paid_at": data["paid_at"],
            "customer": data["customer"]["email"],
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500
