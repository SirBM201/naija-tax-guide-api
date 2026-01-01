import os
import hmac
import hashlib
from flask import Flask, request, abort, jsonify

app = Flask(__name__)

# --- ENV VARS ---
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify")
APP_SECRET = os.getenv("META_APP_SECRET", "")  # optional but recommended


# ---------------------------
# Health check (Koyeb)
# ---------------------------
@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


# ---------------------------
# Signature verification
# ---------------------------
def verify_signature(req) -> bool:
    if not APP_SECRET:
        # Allow requests if secret not set (OK for now)
        return True

    signature = req.headers.get("X-Hub-Signature-256")
    if not signature or not signature.startswith("sha256="):
        return False

    received_hash = signature.split("=", 1)[1]
    payload = req.get_data()

    expected_hash = hmac.new(
        APP_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(received_hash, expected_hash)


# ---------------------------
# Webhook
# ---------------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():

    # Meta verification
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            return challenge, 200

        return abort(403)

    # Incoming events
    if request.method == "POST":
        if not verify_signature(request):
            return abort(403)

        data = request.get_json(silent=True)
        print("📩 Incoming webhook:", data)

        return "EVENT_RECEIVED", 200


# ---------------------------
# Entry point
# ---------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
