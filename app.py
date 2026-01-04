from flask import Flask, request, Response

app = Flask(__name__)

VERIFY_TOKEN = "naija-tax-guide-verify"

@app.route("/webhook", methods=["GET"])
def verify_webhook():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return Response(challenge, status=200)

    return Response("Forbidden", status=403)
