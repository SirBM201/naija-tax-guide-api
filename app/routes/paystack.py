# app/routes/paystack.py
import os
import uuid
import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase

paystack_bp = Blueprint("paystack", __name__)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
PAYSTACK_CALLBACK_URL = os.getenv("PAYSTACK_CALLBACK_URL", "").strip()

# Amounts are in KOBO (₦3000 = 300000 kobo)
PLAN_PRICES = {
    "monthly": 300000,
    "quarterly": 800000,
    "yearly": 3000000,
}

@paystack_bp.post("/paystack/init")
def init_payment():
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not configured"}), 500

    data = request.get_json(silent=True) or {}

    account_id = (data.get("account_id") or "").strip()
    email = (data.get("email") or "").strip()
    plan_code = (data.get("plan_code") or "").strip().lower()

    if not account_id or not email or not plan_code:
        return jsonify({"ok": False, "error": "Missing required fields: account_id, email, plan_code"}), 400

    if plan_code not in PLAN_PRICES:
        return jsonify({"ok": False, "error": "Invalid plan_code"}), 400

    reference = f"NTG-{uuid.uuid4()}"
    amount = PLAN_PRICES[plan_code]

    payload = {
        "email": email,
        "amount": amount,
        "reference": reference,
        "metadata": {
            "account_id": account_id,
            "plan_code": plan_code,
        },
    }

    # Only include callback_url if set (Paystack allows it)
    if PAYSTACK_CALLBACK_URL:
        payload["callback_url"] = PAYSTACK_CALLBACK_URL

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers=headers,
            timeout=20,
        )
    except requests.RequestException as e:
        return jsonify({"ok": False, "error": f"Paystack request failed: {str(e)}"}), 502

    try:
        pdata = resp.json()
    except Exception:
        return jsonify({"ok": False, "error": "Paystack returned non-JSON response", "status_code": resp.status_code}), 502

    if not pdata.get("status"):
        # Keep Paystack payload for debugging
        return jsonify({"ok": False, "error": "Paystack init failed", "paystack": pdata}), 400

    auth_url = (pdata.get("data") or {}).get("authorization_url")
    if not auth_url:
        return jsonify({"ok": False, "error": "Paystack init missing authorization_url", "paystack": pdata}), 502

    # Save pending transaction
    sb = supabase()
    sb.table("paystack_tx").insert({
        "reference": reference,
        "account_id": account_id,
        "plan_code": plan_code,
        "amount_kobo": amount,
        "status": "pending",
    }).execute()

    return jsonify({
        "ok": True,
        "authorization_url": auth_url,
        "reference": reference,
    }), 200
