# app/routes/whatsapp_routes.py
import os
import logging
from flask import Blueprint, request, jsonify

from app.services.whatsapp import wa_send_text
from message_router import route_message

bp = Blueprint("whatsapp", __name__)

WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WHATSAPP_WEBHOOK_SECRET = os.getenv("WHATSAPP_WEBHOOK_SECRET", "").strip()  # optional extra guard


def _safe_str(x) -> str:
    return "" if x is None else str(x)


@bp.get("/whatsapp/webhook")
def whatsapp_verify():
    """
    Meta verification handshake:
    GET /whatsapp/webhook?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and WHATSAPP_VERIFY_TOKEN and token == WHATSAPP_VERIFY_TOKEN:
        return challenge, 200

    return "forbidden", 403


@bp.post("/whatsapp/webhook")
def whatsapp_webhook():
    """
    WhatsApp Cloud API webhook receiver.
    Respond FAST with 200 OK.
    """
    # Optional extra guard (your own secret header)
    if WHATSAPP_WEBHOOK_SECRET:
        got = request.headers.get("X-Webhook-Secret", "").strip()
        if got != WHATSAPP_WEBHOOK_SECRET:
            return "forbidden", 403

    data = request.get_json(silent=True) or {}

    try:
        # Cloud API shape:
        # entry[].changes[].value.messages[] ...
        entry = (data.get("entry") or [])
        for e in entry:
            changes = (e.get("changes") or [])
            for c in changes:
                value = (c.get("value") or {})
                messages = (value.get("messages") or [])
                for m in messages:
                    msg_type = (m.get("type") or "").lower()
                    if msg_type != "text":
                        continue

                    text = (((m.get("text") or {}).get("body")) or "").strip()
                    wa_from = (m.get("from") or "").strip()  # sender WA number (usually without +)
                    if not wa_from or not text:
                        continue

                    # Use same engine via message_router
                    sender_key = f"wa:{_safe_str(wa_from)}"
                    reply = route_message(sender_key, text)

                    # Reply to user
                    # WA "to" expects the sender phone in the same format "from" provides.
                    wa_send_text(wa_from, reply)

    except Exception as e:
        logging.exception("WhatsApp inbound handling failed: %s", e)

    # Always ACK quickly
    return "ok", 200


@bp.get("/whatsapp/ping")
def whatsapp_ping():
    return jsonify({"ok": True, "whatsapp": True}), 200
