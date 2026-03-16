from __future__ import annotations

import logging
import os
import re

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.accounts_service import lookup_account, upsert_account
from app.services.ask_service import ask_guarded
from app.services.outbound_service import send_whatsapp_text

bp = Blueprint("whatsapp", __name__)

WA_VERIFY_TOKEN = os.getenv("WHATSAPP_VERIFY_TOKEN", "").strip()
LINK_CODE_RE = re.compile(r"^[A-Z0-9]{8}$")


def _extract_message(body: dict) -> tuple[str, str]:
    entry = (body.get("entry") or [None])[0] or {}
    changes = (entry.get("changes") or [None])[0] or {}
    value = changes.get("value") or {}
    messages = value.get("messages") or []
    if not messages:
        return "", ""

    msg = messages[0]
    from_phone = str(msg.get("from") or "").strip()

    msg_type = msg.get("type")
    text = ""
    if msg_type == "text":
        text = str((msg.get("text") or {}).get("body") or "").strip()

    return from_phone, text


def _try_consume_link_code(provider_user_id: str, raw_text: str) -> dict:
    code = str(raw_text or "").strip().upper()
    if not LINK_CODE_RE.match(code):
        return {"ok": False, "reason": "not_a_code"}

    try:
        res = (
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
        return {"ok": False, "reason": "rpc_error", "error": str(e)}

    row = (res.data or [None])[0]
    if not row:
        return {"ok": False, "reason": "no_rpc_row"}

    if row.get("ok") is True and row.get("auth_user_id"):
        return {"ok": True, "auth_user_id": row.get("auth_user_id")}

    return {"ok": False, "reason": row.get("reason") or "consume_failed", "rpc": row}


@bp.get("/whatsapp/webhook")
def wa_webhook_verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token and WA_VERIFY_TOKEN and token == WA_VERIFY_TOKEN:
        return (challenge or ""), 200
    return "Forbidden", 403


@bp.post("/whatsapp/webhook")
def wa_webhook_receive():
    body = request.get_json(silent=True) or {}

    try:
        from_phone, text = _extract_message(body)
        if not from_phone:
            return jsonify({"ok": True, "ignored": True})

        upsert_account(provider="wa", provider_user_id=from_phone, display_name=None, phone=from_phone)

        lk = lookup_account(provider="wa", provider_user_id=from_phone)
        if not lk.get("ok"):
            send_whatsapp_text(from_phone, "System error. Please try again.")
            return jsonify({"ok": True})

        if not lk.get("linked"):
            if text:
                attempt = _try_consume_link_code(from_phone, text)
                if attempt.get("ok"):
                    send_whatsapp_text(
                        from_phone,
                        "✅ WhatsApp linked successfully!\nNow send your tax question here anytime.",
                    )
                    return jsonify({"ok": True, "linked": True, "linked_now": True})

            send_whatsapp_text(
                from_phone,
                "Your WhatsApp is not linked yet.\n"
                "1) Login on the website\n"
                "2) Generate your LINK CODE\n"
                "3) Reply here with the 8-character code\n\n"
                "Example: 7K9M2H8P",
            )
            return jsonify({"ok": True, "linked": False})

        if not text:
            send_whatsapp_text(from_phone, "Send your question as text and I will reply.")
            return jsonify({"ok": True, "linked": True, "ignored": True, "reason": "no_text"})

        account_id = str(lk.get("account_id") or "").strip()
        if not account_id:
            send_whatsapp_text(from_phone, "System error. Your linked account could not be resolved.")
            return jsonify({"ok": True, "linked": True, "ignored": True, "reason": "missing_account_id"})

        resp = ask_guarded(
            account_id=account_id,
            question=text,
            lang="en",
            channel="whatsapp",
        )

        answer = str(resp.get("answer") or resp.get("message") or "").strip()
        if not answer:
            answer = "I couldn't process that right now. Please try again."

        send_whatsapp_text(from_phone, answer)
        return jsonify({"ok": True, "linked": True, "ask": resp})

    except Exception as e:
        logging.exception("WA webhook error: %s", e)
        return jsonify({"ok": True})
