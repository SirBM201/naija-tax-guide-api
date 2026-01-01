import os
import hmac
import hashlib
from flask import Flask, request, abort, jsonify, Response

app = Flask(__name__)

# -----------------------------
# ENV VARS (set in Koyeb)
# -----------------------------
# Use WHATSAPP_VERIFY_TOKEN in Koyeb; fallback is fine for local.
VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN") or "naija-tax-guide-verify"

# Meta App Secret (App Dashboard -> Settings -> Basic -> App Secret)
# If not set, signature verification is skipped (OK for local; set it for production).
APP_SECRET = (os.getenv("META_APP_SECRET") or "").strip()


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


def verify_signature(req) -> bool:
    """
    Verify Meta webhook signature header: X-Hub-Signature-256: sha256=<hash>
    If APP_SECRET is not set, we skip verification.
    """
    if not APP_SECRET:
        return True  # skip in local/testing

    signature = req.headers.get("X-Hub-Signature-256", "")
    if not signature.startswith("sha256="):
        return False

    provided_hash = signature.split("=", 1)[1].strip()
    payload = req.get_data(cache=False)  # raw bytes

    expected_hash = hmac.new(
        APP_SECRET.encode("utf-8"),
        msg=payload,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(provided_hash, expected_hash)


@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # -----------------------------
    # 1) Webhook verification (GET)
    # -----------------------------
    if request.method == "GET":
        mode = request.args.get("hub.mode", "")
        token = request.args.get("hub.verify_token", "")
        challenge = request.args.get("hub.challenge", "")

        if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
            # IMPORTANT: return the challenge as plain text
            return Response(challenge, status=200, mimetype="text/plain")

        return abort(403)

    # -----------------------------
    # 2) Incoming events (POST)
    # -----------------------------
    if not verify_signature(request):
        return abort(403)

    data = request.get_json(silent=True)
    if data is None:
        # Still acknowledge quickly
        return Response("EVENT_RECEIVED", status=200, mimetype="text/plain")

    # Log event (you can replace with DB save later)
    print("📩 Incoming webhook event:", data)

    return Response("EVENT_RECEIVED", status=200, mimetype="text/plain")


if __name__ == "__main__":
    # Koyeb provides PORT. Default to 8000 locally.
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=False)
