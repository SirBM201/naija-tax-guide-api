import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

# --------------------------------------------------
# ENV
# --------------------------------------------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

# Optional: comma-separated allowed origins
# Example:
# CORS_ORIGINS="http://localhost:3000,https://thecre8hub.com,https://www.thecre8hub.com"
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").strip()

DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://thecre8hub.com",
    "https://www.thecre8hub.com",
]

def parse_origins(value: str):
    if not value:
        return DEFAULT_ORIGINS
    return [x.strip() for x in value.split(",") if x.strip()]

# --------------------------------------------------
# APP
# --------------------------------------------------
app = Flask(__name__)

# --------------------------------------------------
# CORS (FIXED & SAFE)
# --------------------------------------------------
CORS(
    app,
    resources={r"/*": {"origins": parse_origins(CORS_ORIGINS)}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=86400,
)

# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

# --------------------------------------------------
# PAYSTACK VERIFY
# --------------------------------------------------
@app.post("/paystack/verify")
def paystack_verify():
    """
    Body:
    {
      "reference": "xxxx"
    }

    Returns:
    {
      ok: true,
      paid: true/false,
      reference,
      status,
      amount,
      currency,
      customer_email
    }
    """

    if not PAYSTACK_SECRET_KEY:
        return jsonify({
            "ok": False,
            "error": "PAYSTACK_SECRET_KEY not set"
        }), 500

    data = request.get_json(silent=True) or {}
    reference = str(data.get("reference", "")).strip()

    if not reference:
        return jsonify({
            "ok": False,
            "error": "reference required"
        }), 400

    try:
        url = f"https://api.paystack.co/transaction/verify/{reference}"
        headers = {
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }

        resp = requests.get(url, headers=headers, timeout=30)
        payload = resp.json()

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": "paystack_unreachable",
            "detail": str(e)
        }), 502

    # Paystack logical failure
    if not payload or payload.get("status") is not True:
        return jsonify({
            "ok": False,
            "error": "paystack_verify_failed",
            "detail": payload
        }), 400

    d = payload.get("data") or {}
    status = str(d.get("status", "")).lower()  # success / failed / abandoned
    paid = status == "success"

    # amount is in kobo
    amount_kobo = d.get("amount")
    amount = amount_kobo / 100 if isinstance(amount_kobo, (int, float)) else None

    customer = d.get("customer") or {}
    customer_email = customer.get("email")

    return jsonify({
        "ok": True,
        "paid": paid,
        "reference": reference,
        "status": status,
        "currency": d.get("currency"),
        "amount_kobo": amount_kobo,
        "amount": amount,
        "customer_email": customer_email,
        "gateway_response": d.get("gateway_response"),
    }), 200
