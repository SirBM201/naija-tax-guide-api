# app.py

import sys
import os
import hmac
import hashlib
import json
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS

# --------------------------------------------------
# FORCE correct module resolution
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# --------------------------------------------------
# App setup
# --------------------------------------------------
app = Flask(__name__)
CORS(app)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()

# --------------------------------------------------
# Health
# --------------------------------------------------
@app.get("/health")
def health():
    return jsonify({"ok": True})

# --------------------------------------------------
# Route inspector (DEBUG)
# --------------------------------------------------
@app.get("/__routes")
def list_routes():
    rules = sorted(
        f"{r.rule} -> {','.join(sorted(r.methods))}"
        for r in app.url_map.iter_rules()
    )
    return jsonify({"count": len(rules), "routes": rules})

# --------------------------------------------------
# Paystack Webhook
# --------------------------------------------------
@app.post("/webhooks/paystack")
def paystack_webhook():
    logging.info("📥 Paystack webhook HIT")

    raw_body = request.get_data()
    signature = request.headers.get("x-paystack-signature", "")

    if not PAYSTACK_SECRET_KEY:
        logging.error("PAYSTACK_SECRET_KEY not set")
        return jsonify({"error": "server_misconfigured"}), 500

    computed = hmac.new(
        PAYSTACK_SECRET_KEY.encode(),
        raw_body,
        hashlib.sha512,
    ).hexdigest()

    if not hmac.compare_digest(computed, signature):
        logging.warning("Invalid Paystack signature")
        return jsonify({"error": "invalid_signature"}), 401

    payload = request.json or {}
    logging.info(f"✅ Paystack event received: {payload.get('event')}")

    return jsonify({"ok": True})
