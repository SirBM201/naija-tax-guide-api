import os
import hmac
import hashlib
import logging
from flask import Flask, request, abort, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# REQUIRED: set this in Koyeb exactly as you type it in Meta Webhooks "Verify token"
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN")
if not VERIFY_TOKEN:
    raise RuntimeError("Missing env var WHATSAPP_VERIFY_TOKEN in Koyeb")

# OPTIONAL but recommended for production (Meta App Secret)
APP_SECRET = os.getenv("META_APP_SECRET", "")

@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "ok", "service": "naija-tax-guide-api"}), 200

# Health check compatible with ALL Flask versions
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


def verify_signature(req) -> bool:
    """
    Verify Meta signature for POST webhooks.
    If META_APP_SECRET is not set, skip verification (OK for testing).
    """
    if not APP_SECRET:
        return True

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    provided_hash = signature.split("=", 1)[1]
    payload = req.get_data()  # raw bytes

    expected_hash = hmac.new(
        APP_SECRET.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(provided_hash, expected_hash)


@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # --- Meta webhook verification ---
    if request.method == "GET":
        mode = request.args.get("hub.mode", "")
        token = request.args.get("hub.verify_token", "")
        challenge = request.args.get("hub.challenge", "")

        logging.info(f"Webhook verify GET: mode={mode}, token_match={token == VERIFY_TOKEN}")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            # Must return the challenge as plain text
            return str(challenge), 200

        return abort(403)

    # --- Incoming webhook events ---
    if request.method == "POST":
        if not verify_signature(request):
            logging.warning("Invalid webhook signature")
            return abort(403)

        data = request.get_json(silent=True) or {}
        logging.info(f"Incoming webhook event: {data}")

        return "EVENT_RECEIVED", 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
