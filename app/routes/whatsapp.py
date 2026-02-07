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


def _extract_wa_text(body: dict) -> tuple[str, str]:
    """
    Returns (from_phone, text)
    """
    entry = (body.get("entry") or [None])[0] or {}
    changes = (entry.get("changes") or [None])[0] or {}
    value = changes.get("value") or {}
    messages = value.get("messages") or []
    if not messages:
        return "", ""

    msg = messages[0]
    from_phone = (msg.get("from") or "").strip()

    msg_type = (msg.get("type") or "").strip().lower()
    text = ""

    if msg_type == "text":
        text = ((msg.get("text") or {}).get("body") or "").strip()
    # You can extend later for interactive/button replies if needed.

    return from_phone, text


def _try_consume_link_code(provider: str, provider_user_id: str, code: str) -> dict:
    """
    Calls Supabase RPC: consume_link_token(p_provider, p_code, p_provider_user_id)
    Expected to return a row with at least:
      ok:boolean, auth_user_id:uuid (when ok=true)
    """
    try:
        res = supabase().rpc(
            "consume_link_token",
            {
                "p_provider": provider,
                "p_code": code,
                "p_provider_user_id": provider_user_id,
            },
        ).execute()
    except Exception as e:
        return {"ok": False, "error": f"RPC error: {str(e)}"}

    row = (res.data or [None])[0]
    if not row:
        return {"ok": False, "error": "No RPC row returned."}

    # Normalize
    ok = bool(row.get("ok"))
    auth_user_id = row.get("auth_user_id")

    return {"ok": ok, "auth_user_id": auth_user_id, "raw": row}


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

    Behavior:
    1) Upsert account shell
    2) If linked -> acknowledge
    3) If not linked:
       - If text is 8-char code -> consume_link_token RPC, then upsert_account_link
       - Else -> tell user how to link
    """
    body = request.get_json(silent=True) or {}

    try:
        from_phone, text = _extract_wa_text(body)

        # Always ACK quickly (Meta retries if you error)
        if not from_phone:
            return jsonify({"ok": True, "ignored": True})

        # 1) create/update account shell
        upsert_account(
            provider="wa",
            provider_user_id=from_phone,
            display_name=None,
            phone=from_phone,
        )

        # 2) lookup link status
        lk = lookup_account(provider="wa", provider_user_id=from_phone)
        if not lk.get("ok"):
            _wa_send_text(from_phone, "System error. Please try again.")
            return jsonify({"ok": True})

        if lk.get("linked"):
            if text:
                _wa_send_text(from_phone, f"Received: {text}\n(Linked ✅)")
            else:
                _wa_send_text(from_phone, "Linked ✅")
            return jsonify({"ok": True, "linked": True})

        # 3) Not linked -> if user sent code, try to link
        code = (text or "").strip().upper()
        if code and LINK_CODE_RE.match(code):
            consume = _try_consume_link_code("wa", from_phone, code)
            if consume.get("ok") and consume.get("auth_user_id"):
                auth_user_id = str(consume["auth_user_id"])

                # Write the binding into accounts table
                link_res = upsert_account_link(
                    provider="wa",
                    provider_user_id=from_phone,
                    auth_user_id=auth_user_id,
                    display_name=None,
                    phone=from_phone,
                )
                if link_res.get("ok"):
                    _wa_send_text(
                        from_phone,
                        "✅ Linked successfully!\nYou can now send your questions here anytime.",
                    )
                    return jsonify({"ok": True, "linked": True})

                _wa_send_text(from_phone, "Link succeeded but saving failed. Please try again.")
                return jsonify({"ok": True, "linked": False})

            _wa_send_text(
                from_phone,
                "❌ Invalid or expired LINK CODE.\n"
                "Please login on the website and generate a NEW LINK CODE, then send it here.\n"
                "Example: 7K9M2H8P",
            )
            return jsonify({"ok": True, "linked": False})

        # Otherwise: instruct linking
        _wa_send_text(
            from_phone,
            "Your WhatsApp is not linked yet.\n"
            "Please login on the website and generate your LINK CODE, then reply here with the 8-character code.\n"
            "Example: 7K9M2H8P",
        )
        return jsonify({"ok": True, "linked": False})

    except Exception as e:
        logging.exception("WA webhook error: %s", e)
        return jsonify({"ok": True})  # don't make Meta retry forever
