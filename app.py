import os
import hmac
import hashlib
from flask import Flask, request, abort, Response, jsonify

app = Flask(__name__)

# ============================
# Environment variables
# ============================
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "naija-tax-guide-verify")
APP_SECRET = os.getenv("META_APP_SECRET", "")  # Optional but recommended


# ============================
# Health & root (Koyeb checks)
# ============================
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "naija-tax-guide-api",
        "status": "ok"
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ============================
# Meta signature verification
# ============================
def verify_signature(req) -> bool:
    """
    Verifies X-Hub-Signature-256 from Meta.
    If APP_SECRET is not set, verification is skipped.
    """
    if not APP_SECRET:
        return True  # allow during setup/testing

    signature = req.headers.get("X-Hub-Signature-256")
    if not signature or not signature.startswith("sha256="):
        return False

    received_hash = signature.split("=", 1)[1]
    expected_hash = hmac.new(
        APP_SECRET.encode("utf-8"),
        msg=req.get_data(),
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(received_hash, expected_hash)


# ============================
# Webhook endpoint (Meta)
# ============================
@app.route("/webhook", methods=["GET", "POST"])
def webhook():

    # ---- Verification handshake ----
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            # MUST return raw challenge as text
            return Response(challenge, status=200, mimetype="text/plain")

        return abort(403)

    # ---- Incoming events ----
    if request.method == "POST":

        if not verify_signature(request):
            return abort(403)

        payload = request.get_json(silent=True) or {}
        print("📩 Incoming webhook event:")
        print(payload)

        # WhatsApp / Meta requires fast 200 OK
        return Response("EVENT_RECEIVED", status=200, mimetype="text/plain")


# ============================
# App entrypoint (Koyeb)
# ============================
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
