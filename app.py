import os
import json
import hmac
import hashlib
from flask import Flask, request, jsonify
from supabase import create_client

app = Flask(__name__)

# --------------------
# ENV
# --------------------
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN")
PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --------------------
# HEALTH CHECK
# --------------------
@app.route("/", methods=["GET"])
def health():
    return "OK", 200

# --------------------
# WEBHOOK (GET + POST)
# --------------------
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    # ----------------
    # VERIFY (META)
    # ----------------
    if request.method == "GET":
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode == "subscribe" and token == VERIFY_TOKEN:
            return challenge, 200

        return "Forbidden", 403

    # ----------------
    # RECEIVE MESSAGE
    # ----------------
    payload = request.get_json(force=True)

    # LOG EVENT
    supabase.table("webhook_events").insert({
        "provider": "whatsapp",
        "payload": payload
    }).execute()

    try:
        entry = payload["entry"][0]
        change = entry["changes"][0]
        value = change["value"]

        messages = value.get("messages", [])
        if not messages:
            return jsonify({"status": "no_message"}), 200

        msg = messages[0]
        sender = msg["from"]
        text = msg.get("text", {}).get("body", "")

        # SAVE USER
        supabase.table("wa_users").upsert({
            "wa_phone": sender
        }).execute()

        # AUTO REPLY
        send_whatsapp_message(
            sender,
            "Welcome to Naija Tax Guide 🇳🇬\n\nReply *HELP* to see available options."
        )

    except Exception as e:
        print("Webhook error:", e)

    return jsonify({"status": "ok"}), 200

# --------------------
# SEND WHATSAPP MESSAGE
# --------------------
def send_whatsapp_message(to, message):
    import requests

    url = f"https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": message}
    }

    requests.post(url, headers=headers, json=data)

# --------------------
# RUN
# --------------------
if __name__ == "__main__":
    port = int(os.getenv("APP_PORT", 8000))
    app.run(host="0.0.0.0", port=port)
