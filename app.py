# app.py (REPLACE COMPLETELY)
import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Flask, request, jsonify
from flask_cors import CORS

try:
    from supabase import create_client  # optional
except Exception:
    create_client = None  # type: ignore


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)
from flask import jsonify

@app.get("/routes")
@app.get("/_routes")
def list_routes():
    out = []
    for r in app.url_map.iter_rules():
        methods = sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")])
        out.append({"rule": str(r), "methods": methods, "endpoint": r.endpoint})
    return jsonify({"count": len(out), "routes": sorted(out, key=lambda x: x["rule"])})

    # -----------------------------
    # ENV
    # -----------------------------
    app.config["PAYSTACK_SECRET_KEY"] = (os.getenv("PAYSTACK_SECRET_KEY", "") or "").strip()
    app.config["PAYSTACK_WEBHOOK_SECRET"] = (os.getenv("PAYSTACK_WEBHOOK_SECRET", "") or "").strip()
    if not app.config["PAYSTACK_WEBHOOK_SECRET"]:
        # fallback to PAYSTACK_SECRET_KEY (Paystack commonly uses secret key for signature)
        app.config["PAYSTACK_WEBHOOK_SECRET"] = app.config["PAYSTACK_SECRET_KEY"]

    app.config["SUPABASE_URL"] = (os.getenv("SUPABASE_URL", "") or "").strip()
    app.config["SUPABASE_SERVICE_ROLE_KEY"] = (os.getenv("SUPABASE_SERVICE_ROLE_KEY", "") or "").strip()

    # optional Supabase client (only if keys exist)
    supabase = None
    if create_client and app.config["SUPABASE_URL"] and app.config["SUPABASE_SERVICE_ROLE_KEY"]:
        try:
            supabase = create_client(app.config["SUPABASE_URL"], app.config["SUPABASE_SERVICE_ROLE_KEY"])
            logging.info("Supabase client initialized.")
        except Exception as e:
            logging.warning("Supabase init failed: %s", e)

    # -----------------------------
    # ROUTES
    # -----------------------------
    @app.get("/health")
    def health():
        return jsonify({"ok": True, "ts": now_utc_iso()})

    @app.get("/routes")
    def routes():
        out = []
        for r in app.url_map.iter_rules():
            methods = sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")])
            out.append({"rule": str(r), "methods": methods, "endpoint": r.endpoint})
        out.sort(key=lambda x: x["rule"])
        return jsonify(out)

    # Paystack webhook endpoint (THIS is what Paystack should call)
    @app.post("/webhooks/paystack")
    def paystack_webhook():
        raw = request.get_data() or b""
        sig = request.headers.get("x-paystack-signature", "") or ""

        secret = app.config["PAYSTACK_WEBHOOK_SECRET"]
        if not secret:
            logging.error("PAYSTACK_WEBHOOK_SECRET/PAYSTACK_SECRET_KEY not set")
            return "secret not set", 500

        expected = hmac.new(secret.encode("utf-8"), raw, hashlib.sha512).hexdigest()
        if not hmac.compare_digest(expected, sig):
            logging.warning("Invalid paystack signature")
            return "invalid signature", 401

        try:
            event = json.loads(raw.decode("utf-8"))
        except Exception:
            logging.exception("Invalid JSON payload from Paystack")
            return "invalid json", 400

        event_name = event.get("event")
        data = event.get("data") or {}
        reference = data.get("reference")

        logging.info("Paystack webhook received: event=%s reference=%s", event_name, reference)

        # Minimal safe handling: ACK everything valid so Paystack stops retrying
        # You can expand this later for:
        # - charge.success -> activate subscription
        # - refund.processed / refund.failed -> update records
        # - subscription.create / subscription.disable etc (if you use Paystack subscriptions)
        #
        # Example: write to Supabase (optional)
        if supabase:
            try:
                supabase.table("paystack_events").insert({
                    "event": event_name,
                    "reference": reference,
                    "payload": event,
                    "received_at": now_utc_iso(),
                }).execute()
            except Exception as e:
                # do NOT fail webhook delivery if logging fails
                logging.warning("Supabase log insert failed: %s", e)

        return jsonify({"ok": True})

    # Optional: allow GET for quick browser checks (Paystack uses POST)
    @app.get("/webhooks/paystack")
    def paystack_webhook_get():
        return jsonify({"ok": True, "hint": "Send POST from Paystack to this same URL."})

    return app


# Gunicorn looks for this variable when you run: gunicorn ... app:app
app = create_app()


# Local dev convenience (Koyeb will ignore this)
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
