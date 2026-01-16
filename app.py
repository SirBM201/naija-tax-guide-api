# app.py (TOP OF FILE — FIRST LINES)

import sys
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS

# Import and register routes from modules
from paystack.webhook import bp as paystack_webhook_bp

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)

    # Health
    @app.get("/health")
    def health():
        return jsonify({"ok": True})

    # Debug routes listing (I am adding BOTH to avoid proxy issues with underscore paths)
    @app.get("/routes")
    @app.get("/_routes")
    def routes():
        rules = []
        for r in app.url_map.iter_rules():
            methods = ",".join(sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")]))
            rules.append(f"{r.rule} -> {methods}")
        rules.sort()
        return jsonify({"count": len(rules), "routes": rules})

    # Register Paystack webhook blueprint
    app.register_blueprint(paystack_webhook_bp)

    return app

# Gunicorn entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
