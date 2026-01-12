import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

# Comma-separated list of allowed origins for CORS
# Example:
# CORS_ORIGINS="http://localhost:3000,https://thecre8hub.com,https://www.thecre8hub.com"
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "").strip()

DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://thecre8hub.com",
    "https://www.thecre8hub.com",
]

def _parse_origins(value: str):
    if not value:
        return DEFAULT_ORIGINS
    parts = [x.strip() for x in value.split(",")]
    return [x for x in parts if x]

app = Flask(__name__)

# ---- CORS (important) ----
CORS(
    app,
    resources={r"/*": {"origins": _parse_origins(CORS_ORIGINS)}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=86400,
)

@app.get("/health")
def health():
    return jsonify({"ok": True})

@app.post("/paystack/verify")
def paystack_verify():
    """
    Body: { "reference": "xxxx" }
    Returns: { ok: true, paid: true/false, reference, status, amount, currency, gateway_response, customer_email }
    """
    if not PAYSTACK_SECRET_KEY:
        return jsonify({"ok": False, "error": "PAYSTACK_SECRET_KEY not set"}), 500

    data = request.get_json(silent=True) or {}
    reference = str(data.get("reference", "")).strip()

    if not reference:
        return jsonify({"ok": False, "error": "reference required"}), 400

    url = f"https://api.paystack.co/transaction/verify/{reference}"
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}

    try:
        r = requests.get(url, headers=headers, timeout=30)
        payload = r.json() if r.content else {}
    except Exception as e:
        # network / JSON parsing error
        return jsonify({"ok": False, "error": "paystack_unreachable", "detail": str(e)}), 502

    # Paystack uses HTTP 200 for many logical errors, so check payload["status"]
    if r.status_code >= 400:
        return jsonify({"ok": False, "error": "paystack_http_error", "detail": payload}), 502

    if not payload or payload.get("status") is not True:
        return jsonify({"ok": False, "error": "paystack_verify_failed", "detail": payload}), 400

    d = payload.get("data") or {}
    paystack_status = str(d.get("status", "")).lower()   # "success", "failed", "abandoned", etc.
    paid = (paystack_status == "success")

    # amount is in kobo
    amount_kobo = d.get("amount")
    amount_ngn = None
    try:
        if isinstance(amount_kobo, (int, float)):
            amount_ngn = float(amount_kobo) / 100.0
    except Exception:
        amount_ngn = None

    customer = d.get("customer") or {}
    customer_email = customer.get("email")

    return jsonify({
        "ok": True,
        "paid": paid,
        "reference": reference,
        "status": paystack_status,
        "gateway_response": d.get("gateway_response"),
        "currency": d.get("currency"),
        "amount_kobo": amount_kobo,
        "amount": amount_ngn,
        "customer_email": customer_email,
        "raw": d,  # keep for debugging; remove later if you want
    }), 200
