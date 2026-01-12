import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

# -------------------------------------------------
# ENV
# -------------------------------------------------
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
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
    return [v.strip() for v in value.split(",") if v.strip()]

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

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.post("/paystack/verify")
def paystack_verify():
    """
    Body:
      {
        "reference": "paystack_reference_here"
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
            "error": "reference_required"
        }), 400

    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        payload = resp.json()
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": "paystack_unreachable",
            "detail": str(e)
        }), 502

    if resp.status_code != 200:
        return jsonify({
            "ok": False,
            "error": "paystack_http_error",
            "detail": payload
        }), 502

    if payload.get("status") is not True:
        return jsonify({
            "ok": False,
            "error": "paystack_verify_failed",
            "detail": payload
        }), 400

    data = payload.get("data", {})
    status = data.get("status", "").lower()
    paid = status == "success"

    amount_kobo = data.get("amount")
    amount = amount_kobo / 100 if isinstance(amount_kobo, (int, float)) else None

    customer = data.get("customer") or {}

    return jsonify({
        "ok": True,
        "paid": paid,
        "reference": reference,
        "status": status,
        "amount": amount,
        "currency": data.get("currency"),
        "gateway_response": data.get("gateway_response"),
        "customer_email": customer.get("email"),
        "raw": data
    })
