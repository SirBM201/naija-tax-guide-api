# app/routes/whatsapp.py
from __future__ import annotations

import os
import re
import logging
import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.services.accounts_service import (
    upsert_account,
    lookup_account,
    upsert_account_link,
)

bp = Blueprint("whatsapp", __name__)

WA_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WA_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()

API_BASE = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"

LINK_CODE_RE = re.compile(r"^[A-Z0-9]{8}$")


def _wa_send_text(to_phone: str, text: str) -> None:
    if not (WA_ACCESS_TOKEN and WA_PHONE_NUMBER_ID):
        logging.warning("WhatsApp env not set (WHATSAPP_ACCESS_TOKEN/WHATSAPP_PHONE_NUMBER_ID)")
        return

    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "text",
        "text": {"preview_url": False, "body": text},
    }
    headers = {
        "Authorization": f"Bearer {WA_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }

    try:
        r = requests.post(API_BASE, json=payload, headers=headers, timeout=15)
        if r.status_code >= 300:
            logging.warning("WA send failed: %s %s", r.status_code, r.text)
    except Exception as e:
        logging.exception("WA send exception: %s", e)


def _consume_link_code(provider: str, code: str, provider_user_id: str) -> dict:
    """
    Calls RPC: public.consume_link_token(p_provider text, p_code text, p_provider_user_id text)
    Expected return: a row with at least:
      ok boolean, auth_user_id uuid (when ok=true)
    """
    res = supabase().rpc(
        "consume_link_token",
        {
            "p_provider": provider,
            "p_code": code,
            "p_provider_user_id": provider_user_id,
        },
    ).execute()
    return (res.data or [None])[0] or {}


@bp.get("/whatsapp/webhook")
def wa_webhook_verify():
    """
    Meta webhook verification:
    GET ?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    """
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token and WA_VERIFY_TOKEN and token == WA_VERIFY_TOKEN:
        return (challenge or ""), 200
    return "Forbidden", 403


@bp.post("/whatsapp/webhook")
def wa_webhook_receive():
    """
    Receives WhatsApp messages.
    Flow:
      1) Upsert "shell" account row for (wa, provider_user_id)
      2) If not linked:
           - If message is 8-char code: consume RPC + upsert auth_user_id link
           - Else: ask user to send code
      3) If linked: acknowledge (later you can forward to /ask)
    """
    body = request.get_json(silent=True) or {}

    try:
        entry = (body.get("entry") or [None])[0] or {}
        changes = (entry.get("changes") or [None])[0] or {}
        value = changes.get("value") or {}
        messages = value.get("messages") or []
        if not messages:
            return jsonify({"ok": True, "ignored": True})

        msg = messages[0]
        from_phone = (msg.get("from") or "").strip()  # sender WA id (phone)
        msg_type = msg.get("type")

        text = ""
        if msg_type == "text":
            text = ((msg.get("text") or {}).get("body") or "").strip()

        # Create/update account shell
        upsert_account(
            provider="wa",
            provider_user_id=from_phone,
            display_name=None,
            phone=from_phone,
        )

        # Lookup link status
        lk = lookup_account(provider="wa", provider_user_id=from_phone)
        if not lk.get("ok"):
            _wa_send_text(from_phone, "System error. Please try again.")
            return jsonify({"ok": True})

        # If NOT linked, try to consume code (if user sent one)
        if not lk.get("linked"):
            candidate = (text or "").upper().strip()
            if candidate and LINK_CODE_RE.match(candidate):
                try:
                    out = _consume_link_code("wa", candidate, from_phone)
                    if out.get("ok") is True and out.get("auth_user_id"):
                        upsert_account_link(
                            provider="wa",
                            provider_user_id=from_phone,
                            auth_user_id=str(out.get("auth_user_id")),
                            display_name=None,
                            phone=from_phone,
                        )
                        _wa_send_text(from_phone, "Linked ✅. You can now ask your question here anytime.")
                        return jsonify({"ok": True, "linked": True, "just_linked": True})

                    _wa_send_text(
                        from_phone,
                        "Invalid or expired code.\n"
                        "Please login on the website and generate a NEW LINK CODE, then send it here.",
                    )
                    return jsonify({"ok": True, "linked": False})
                except Exception as e:
                    logging.exception("WA consume_link_token failed: %s", e)
                    _wa_send_text(from_phone, "System error while linking. Please try again.")
                    return jsonify({"ok": True, "linked": False})

            _wa_send_text(
                from_phone,
                "Your WhatsApp is not linked yet.\n"
                "Please login on the website and generate your LINK CODE, then reply here with the 8-character code.\n"
                "Example: 7K9M2H8P",
            )
            return jsonify({"ok": True, "linked": False})

        # Linked path (later: forward to /ask)
        if text:
            _wa_send_text(from_phone, f"Received: {text}\n(Linked ✅)")

        return jsonify({"ok": True, "linked": True})

    except Exception as e:
        logging.exception("WA webhook error: %s", e)
        # Don't make Meta retry forever.
        return jsonify({"ok": True})
