import os
import hmac
import hashlib
from flask import Flask, request, abort, jsonify

app = Flask(__name__)

# --- ENV VARS (set these in Koyeb) ---
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify")
APP_SECRET = os.getenv("META_APP_SECRET", "")  # Meta App Secret (for signature verification)

# Optional: for health checks
@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


def verify_signature(req) -> bool:
    """
    Verifies Meta webhook signature (X-Hub-Signature-256).
    If META_APP_SECRET is not set, we skip verification (OK for local testing, not recommended for prod).
    """
    if not APP_SECRET:
        # Skip verification if not configured
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
    # ---- Webhook verification (Meta) ----
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            print("✅ Webhook verified successfully")
            return challenge, 200

        print("❌ Webhook verification failed")
        return abort(403)

    # ---- Incoming events ----
    if request.method == "POST":
        # Verify request signature (prevents random people from hitting your endpoint)
        if not verify_signature(request):
            print("❌ Invalid signature")
            return abort(403)

        data = request.get_json(silent=True) or {}
        print("📩 Incoming webhook event:")
        print(data)

        # Always respond quickly
        return "EVENT_RECEIVED", 200


if __name__ == "__main__":
    # Koyeb provides PORT env var. Default to 8000 locally.
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
