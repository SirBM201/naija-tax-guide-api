# app/routes/meta.py
from __future__ import annotations

import os
import logging
import requests
from flask import Blueprint, request, jsonify

from app.services.channel_linking_service import extract_code, consume_and_link

bp = Blueprint("meta", __name__)

META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "naija-tax-guide-verify").strip()
META_PAGE_ACCESS_TOKEN = os.getenv("META_PAGE_ACCESS_TOKEN", "").strip()


def _meta_send_text(recipient_id: str, text: str) -> None:
    """
    Works for Facebook Messenger.
    For IG DM, sending requires IG messaging setup; many accounts still accept this endpoint via Graph.
    If IG send fails, we still link successfully; user will just not receive reply.
    """
    if not META_PAGE_ACCESS_TOKEN:
        logging.warning("META_PAGE_ACCESS_TOKEN not set; cannot reply")
        return

    url = "https://graph.facebook.com/v19.0/me/messages"
    params = {"access_token": META_PAGE_ACCESS_TOKEN}
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": text},
    }

    try:
        requests.post(url, params=params, json=payload, timeout=10)
    except Exception as e:
        logging.warning("Meta send failed: %s", e)


@bp.get("/meta/webhook")
def meta_verify():
    mode = (request.args.get("hub.mode") or "").strip()
    token = (request.args.get("hub.verify_token") or "").strip()
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == META_VERIFY_TOKEN and challenge is not None:
        return str(challenge), 200

    return jsonify({"ok": False, "error": "Verification failed"}), 403


@bp.post("/meta/webhook")
def meta_webhook():
    payload = request.get_json(silent=True) or {}

    try:
        # Meta payload format: entry[] -> messaging[] or changes[]
        entries = payload.get("entry") or []
        if not entries:
            return jsonify({"ok": True})

        # --- CASE 1: Messenger "messaging" events ---
        for entry in entries:
            messaging = entry.get("messaging") or []
            for evt in messaging:
                sender = (evt.get("sender") or {}).get("id")
                msg = evt.get("message") or {}
                text = (msg.get("text") or "").strip()

                if not sender or not text:
                    continue

                code = extract_code(text)
                if not code:
                    low = text.lower()
                    if "link" in low or "code" in low or "start" in low:
                        _meta_send_text(sender, "To link Messenger, send your 8-character code here.\nExample: ABC23456")
                    continue

                result = consume_and_link(
                    provider="msgr",
                    code=code,
                    provider_user_id=sender,
                    display_name=None,
                    phone=None,
                )

                if result.get("ok"):
                    _meta_send_text(sender, "✅ Linked successfully! Messenger is now connected to your account.")
                else:
                    _meta_send_text(sender, "❌ Link failed. Invalid/expired code OR already used. Generate a new code and try again.")

        # --- CASE 2: Instagram DM via "changes" (common format) ---
        # Some IG webhooks come in entry[].changes[].value.messages[]
        for entry in entries:
            changes = entry.get("changes") or []
            for ch in changes:
                value = ch.get("value") or {}
                msgs = value.get("messages") or []
                for m in msgs:
                    sender = (m.get("from") or {}).get("id") or (m.get("sender") or {}).get("id")
                    text = (m.get("text") or "").strip()

                    if not sender or not text:
                        continue

                    code = extract_code(text)
                    if not code:
                        continue

                    result = consume_and_link(
                        provider="ig",
                        code=code,
                        provider_user_id=str(sender),
                        display_name=None,
                        phone=None,
                    )

                    # reply best-effort
                    if result.get("ok"):
                        _meta_send_text(str(sender), "✅ Linked successfully! Instagram DM is now connected.")
                    else:
                        _meta_send_text(str(sender), "❌ Link failed. Invalid/expired code OR already used. Generate a new code and try again.")

        return jsonify({"ok": True})

    except Exception as e:
        logging.exception("Meta webhook error: %s", e)
        return jsonify({"ok": True})
