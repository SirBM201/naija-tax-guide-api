# app/routes/paystack.py
import os
import uuid
import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase

paystack_bp = Blueprint("paystack", __name__, url_prefix="/api/paystack")

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

# Price list (kobo)
PLAN_PRICES = {
    "monthly": 300000,    # ₦3,000
    "quarterly": 800000,  # ₦8,000
    "yearly": 3000000,    # ₦30,000
}

@paystack_bp.post("/init")
def init_payment():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "Paystack key not configured"}), 500

    data = request.get_json(silent=True) or {}

    account_id = data.get("account_id")
    email = data.get("email")
    plan_code = data.get("plan_code")

    if not account_id or not email or not plan_code:
        return jsonify({"ok": False, "error": "Missing required fields"}), 400

    if plan_code not in PLAN_PRICES:
        return jsonify({"ok": False, "error": "Invalid plan"}), 400

    reference = f"NTG-{uuid.uuid4()}"
    amount_kobo = PLAN_PRICES[plan_code]

    payload = {
        "email": email,
        "amount": amount_kobo,
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
        pdata = resp.json()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    if not pdata.get("status"):
        return jsonify({"ok": False, "error": pdata}), 400

    # ✅ INSERT PENDING TRANSACTION (THIS WAS MISSING)
    sb = supabase()
    sb.table("paystack_tx").insert({
        "reference": reference,
        "account_id": account_id,
        "plan_code": plan_code,
        "amount_kobo": amount_kobo,
        "currency": "NGN",
        "status": "pending",
    }).execute()

    return jsonify({
        "ok": True,
        "authorization_url": pdata["data"]["authorization_url"],
        "reference": reference,
    })
