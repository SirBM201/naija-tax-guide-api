import os
import hmac
import hashlib
from flask import Flask, request, abort, jsonify, Response

app = Flask(__name__)

# Environment variables
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify")
APP_SECRET = os.getenv("META_APP_SECRET", "")  # Meta App Secret


# --------------------
# Health check (Koyeb)
# --------------------
@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


# --------------------
# Signature verification
# --------------------
def verify_signature(req) -> bool:
    """
    Verify X-Hub-Signature-256 from Meta.
    """
    if not APP_SECRET:
        # Allow verification to pass if secret not set (NOT recommended for prod)
        return True

    signature = req.headers.get("X-Hub-Signature-256")
    if not signature or not signature.startswith("sha256="):
        return False

    received_hash = signature.split("=", 1)[1]
    payload = req.get_data()

    expected_hash = hmac.new(
        APP_SECRET.encode("utf-8"),
        payload,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(received_hash, expected_hash)


# --------------------
# Webhook endpoint
# --------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():

    # ---- Meta verification ----
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            print("✅ Webhook verified by Meta")
            return Response(challenge, status=200, mimetype="text/plain")

        print("❌ Webhook verification failed")
        return abort(403)

    # ---- Incoming events ----
    if request.method == "POST":
        if not verify_signature(request):
            print("❌ Invalid webhook signature")
            return abort(403)

        payload = request.get_json(silent=True) or {}
        print("📩 Incoming webhook event:")
        print(payload)

        # IMPORTANT: Always respond fast
        return Response("EVENT_RECEIVED", status=200)


# --------------------
# App entrypoint
# --------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
