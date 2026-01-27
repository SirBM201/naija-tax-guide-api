# app/routes/whatsapp_routes.py
import os
import logging
from typing import Any, Dict, Optional

import requests
from flask import Blueprint, request, jsonify, current_app

bp = Blueprint("whatsapp", __name__)

# -----------------------------
# ENV
# -----------------------------
WHATSAPP_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN", "").strip()  # Permanent token later; temp token works for testing
WHATSAPP_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
WHATSAPP_API_VERSION = os.getenv("WHATSAPP_API_VERSION", "v22.0").strip()

GRAPH_BASE = f"https://graph.facebook.com/{WHATSAPP_API_VERSION}"


# -----------------------------
# Helpers
# -----------------------------
def _extract_incoming_text(payload: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Returns:
      {"from": "<wa_id>", "text": "<message text>"} or None
    """
    try:
        entry = (payload.get("entry") or [])[0]
        changes = (entry.get("changes") or [])[0]
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            return None

        msg = messages[0]
        wa_from = (msg.get("from") or "").strip()

        msg_type = (msg.get("type") or "").strip()
        if msg_type == "text":
            text = ((msg.get("text") or {}).get("body") or "").strip()
            if text:
                return {"from": wa_from, "text": text}
            return None

        # Optional: handle other types gracefully
        # e.g. button replies, interactive replies, etc.
        if msg_type in ("button", "interactive"):
            # Best-effort fallback
            text = ""
            if msg_type == "button":
                text = ((msg.get("button") or {}).get("text") or "").strip()
            else:
                interactive = msg.get("interactive") or {}
                # could be list_reply / button_reply
                text = (
                    ((interactive.get("button_reply") or {}).get("title") or "").strip()
                    or ((interactive.get("list_reply") or {}).get("title") or "").strip()
                )
            if text:
                return {"from": wa_from, "text": text}
            return None

        return None
    except Exception:
        logging.exception("WhatsApp: failed to parse incoming payload")
        return None


def _send_whatsapp_text(to_wa_id: str, text: str) -> None:
    if not WHATSAPP_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        logging.warning("WhatsApp: missing WHATSAPP_TOKEN or WHATSAPP_PHONE_NUMBER_ID")
        return

    url = f"{GRAPH_BASE}/{WHATSAPP_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WHATSAPP_TOKEN}",
        "Content-Type": "application/json",
    }
    body = {
        "messaging_product": "whatsapp",
        "to": to_wa_id,
        "type": "text",
        "text": {"body": text},
    }

    try:
        r = requests.post(url, headers=headers, json=body, timeout=20)
        if r.status_code >= 300:
            logging.error("WhatsApp send failed: %s %s", r.status_code, r.text[:500])
    except Exception:
        logging.exception("WhatsApp: send message exception")


def _get_answer_via_existing_engine(user_key: str, question: str) -> str:
    """
    This is the key part: it reuses your already-built 'engine' without duplicating logic.
    We call your existing /ask endpoint internally (no internet round-trip).
    """
    try:
        client = current_app.test_client()
        # Most common pattern: POST /ask with {wa_phone, text}
        # If your /ask expects different keys, edit ONLY this payload mapping.
        resp = client.post(
            "/ask",
            json={
                "wa_phone": user_key,     # WhatsApp user id (wa_id) is safest unique key
                "text": question,
                "channel": "whatsapp",
            },
        )
        data = resp.get_json(silent=True) or {}
        if isinstance(data, dict) and data.get("ok") is True and data.get("answer"):
            return str(data["answer"])
        # fallback message if blocked or bad format
        return str(data.get("message") or data.get("reason") or "Sorry, I couldn't process that right now.")
    except Exception:
        logging.exception("WhatsApp: engine call failed")
        return "Sorry — something went wrong on my side. Please try again."


# -----------------------------
# Routes
# -----------------------------
@bp.get("/whatsapp/ping")
def whatsapp_ping():
    ok = bool(WHATSAPP_VERIFY_TOKEN) and bool(WHATSAPP_PHONE_NUMBER_ID)
    return jsonify({"ok": True, "whatsapp": True, "config_ok": ok})


@bp.get("/whatsapp/webhook")
def whatsapp_verify():
    """
    Meta Webhook Verification:
    GET with hub.mode, hub.verify_token, hub.challenge
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    if mode == "subscribe" and token and token == WHATSAPP_VERIFY_TOKEN:
        logging.info("WhatsApp webhook verified OK")
        return challenge, 200

    logging.warning("WhatsApp webhook verify failed (mode=%s)", mode)
    return "forbidden", 403


@bp.post("/whatsapp/webhook")
def whatsapp_webhook():
    """
    Receives inbound WhatsApp messages and replies using the same engine as web+telegram.
    """
    payload = request.get_json(silent=True) or {}

    incoming = _extract_incoming_text(payload)
    if not incoming:
        # This is normal: delivery receipts/status updates also hit this endpoint
        return jsonify({"ok": True, "ignored": True})

    wa_id = incoming["from"]
    text = incoming["text"]
    logging.info("WhatsApp inbound from=%s text=%s", wa_id, text[:200])

    answer = _get_answer_via_existing_engine(user_key=wa_id, question=text)
    _send_whatsapp_text(to_wa_id=wa_id, text=answer)

    return jsonify({"ok": True})
