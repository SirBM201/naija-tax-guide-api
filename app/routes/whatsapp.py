# app/routes/whatsapp.py
from __future__ import annotations

import os
import re
import logging
import requests
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase
from app.services.accounts_service import upsert_account, lookup_account, upsert_account_link

bp = Blueprint("whatsapp", __name__)

WA_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
WA_ACCESS_TOKEN = os.getenv("WHATSAPP_ACCESS_TOKEN", "").strip()
WA_PHONE_NUMBER_ID = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()

API_BASE = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"

CODE_RE = re.compile(r"^[A-Z0-9]{8}$", re.IGNORECASE)


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


def _extract_message(body: dict) -> tuple[str, str]:
    """
    Returns (from_phone, text). If no message, returns ("","").
    """
    entry = (body.get("entry") or [None])[0] or {}
    changes = (entry.get("changes") or [None])[0] or {}
    value = changes.get("value") or {}
    messages = value.get("messages") or []
    if not messages:
        return "", ""

    msg = messages[0]
    from_phone = (msg.get("from") or "").strip()

    msg_type = msg.get("type")
    text = ""
    if msg_type == "text":
        text = ((msg.get("text") or {}).get("body") or "").strip()

    return from_phone, text


def _try_link_with_code(provider_user_id: str, code: str) -> dict:
    """
    Uses Supabase RPC consume_link_token(p_provider, p_code, p_provider_user_id).
    If ok, binds auth_user_id to accounts table.
    """
    try:
        resp = (
            supabase()
            .rpc(
                "consume_link_token",
                {
                    "p_provider": "wa",
                    "p_code": code,
                    "p_provider_user_id": provider_user_id,
                },
            )
            .execute()
        )
    except Exception as e:
        return {"ok": False, "error": f"RPC error: {str(e)}"}

    row = (resp.data or [None])[0] if isinstance(resp.data, list) else resp.data
    if not row or not row.get("ok"):
        return {"ok": False, "reason": "invalid_or_expired_code"}

    auth_user_id = (row.get("auth_user_id") or "").strip()
    if not auth_user_id:
        return {"ok": False, "reason": "no_auth_user_returned"}

    # Persist the link in accounts table (idempotent)
    linked = upsert_account_link(
        provider="wa",
        provider_user_id=provider_user_id,
        auth_user_id=auth_user_id,
        display_name=None,
        phone=provider_user_id,
    )
    if not linked.get("ok"):
        return {"ok": False, "error": linked.get("error") or "Failed to link account"}

    return {"ok": True, "auth_user_id": auth_user_id}


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
    WhatsApp inbound messages:
    - upsert account shell
    - if not linked: ask for link code
    - if user sends 8-char code: consume_link_token RPC and link immediately
    """
    body = request.get_json(silent=True) or {}

    try:
        from_phone, text = _extract_message(body)
        if not from_phone:
            return jsonify({"ok": True, "ignored": True})

        # Create/update account shell
        upsert_account(
            provider="wa",
            provider_user_id=from_phone,
            display_name=None,
            phone=from_phone,
        )

        lk = lookup_account(provider="wa", provider_user_id=from_phone)
        if not lk.get("ok"):
            _wa_send_text(from_phone, "System error. Please try again.")
            return jsonify({"ok": True})

        # If not linked, allow user to submit code directly here
        if not lk.get("linked"):
            if text and CODE_RE.match(text.strip()):
                res = _try_link_with_code(from_phone, text.strip().upper())
                if res.get("ok"):
                    _wa_send_text(
                        from_phone,
                        "✅ Linked successfully.\nYou can now send your questions here anytime.",
                    )
                    return jsonify({"ok": True, "linked": True})

                _wa_send_text(
                    from_phone,
                    "❌ Invalid/expired code.\n"
                    "Please login on the website, generate a NEW LINK CODE, then reply here with the 8-character code.\n"
                    "Example: 7K9M2H8P",
                )
                return jsonify({"ok": True, "linked": False})

            _wa_send_text(
                from_phone,
                "Your WhatsApp is not linked yet.\n"
                "Please login on the website and generate your LINK CODE, then reply here with the 8-character code.\n"
                "Example: 7K9M2H8P",
            )
            return jsonify({"ok": True, "linked": False})

        # Linked user
        if text:
            _wa_send_text(from_phone, f"Received: {text}\n(Linked ✅)")

        return jsonify({"ok": True, "linked": True})

    except Exception as e:
        logging.exception("WA webhook error: %s", e)
        return jsonify({"ok": True})
