# app/routes/inbound.py
from __future__ import annotations

"""
Inbound WhatsApp + Telegram (HARDENED)

✅ Uses canonical accounts.account_id everywhere (NEVER accounts.id)
✅ Fixes the object misuse bug (upsert_account returns {"ok":..., "account":...})
✅ Adds failure exposers so inbound failures show root cause + fix
"""

from flask import Blueprint, request, jsonify

from ..services.accounts_service import upsert_account
from ..services.ask_service import ask_guarded
from ..services.db import supabase_admin
from ..services.outbound_service import send_whatsapp_text, send_telegram_text

bp = Blueprint("inbound", __name__)


def _consume_link(provider: str, code: str, provider_user_id: str):
    provider = (provider or "").strip().lower()
    code = (code or "").strip()
    provider_user_id = (provider_user_id or "").strip()
    if not provider or not code or not provider_user_id:
        return None

    db = supabase_admin()
    res = db.rpc(
        "consume_link_token",
        {
            "p_provider": provider,
            "p_code": code,
            "p_provider_user_id": provider_user_id,
        },
    ).execute()

    return res.data[0] if getattr(res, "data", None) else None


def _maybe_link_from_message(provider: str, text: str, provider_user_id: str):
    txt = (text or "").strip()
    if not txt:
        return None
    if not txt.lower().startswith("link "):
        return None

    code = txt[5:].strip()
    if not code:
        return None

    return _consume_link(provider, code, provider_user_id)


def _json_body():
    return request.get_json(silent=True) or {}


def _extract_whatsapp_text(body: dict):
    try:
        entry = body["entry"][0]
        change = entry["changes"][0]
        value = change["value"]

        messages = value.get("messages")
        if not messages:
            return (None, None)

        msg = messages[0]
        wa_user_id = str(msg.get("from", "")).strip()
        msg_type = msg.get("type")

        if msg_type != "text":
            return (wa_user_id or None, None)

        text = (msg.get("text", {}) or {}).get("body", "") or ""
        return (wa_user_id or None, text.strip() or None)
    except Exception:
        return (None, None)


def _extract_telegram_text(body: dict):
    msg = body.get("message") or body.get("edited_message") or {}
    if not msg and body.get("callback_query"):
        msg = (body.get("callback_query") or {}).get("message") or {}

    if not msg:
        return (None, None, None)

    chat = msg.get("chat") or {}
    tg_chat_id = str(chat.get("id") or "").strip()

    frm = msg.get("from") or {}
    tg_user_id = str(frm.get("id") or "").strip()

    text = (msg.get("text") or "").strip()

    if not tg_chat_id or not tg_user_id or not text:
        return (tg_chat_id or None, tg_user_id or None, None)

    return (tg_chat_id, tg_user_id, text)


def _extract_account_id_from_upsert(result: dict) -> str | None:
    """
    upsert_account returns:
      {"ok": True, "account_id": "...", "account": {...}}
    but older versions sometimes returned:
      {"ok": True, "account": {...}} where account["account_id"] exists

    This helper safely extracts canonical account_id.
    """
    if not isinstance(result, dict):
        return None

    v = str(result.get("account_id") or "").strip()
    if v:
        return v

    acct = result.get("account") or {}
    if isinstance(acct, dict):
        v2 = str(acct.get("account_id") or "").strip()
        if v2:
            return v2

    return None


# -------------------------
# WhatsApp inbound
# -------------------------
@bp.post("/inbound/whatsapp")
def whatsapp_inbound():
    body = _json_body()
    wa_user_id, text = _extract_whatsapp_text(body)

    if not wa_user_id:
        return jsonify({"ok": True, "ignored": True, "reason": "no_sender_or_status"}), 200

    if not text:
        return jsonify({"ok": True, "ignored": True, "reason": "no_text"}), 200

    # ✅ ensure account exists (provider for account table should match your canonical mapping)
    up = upsert_account(provider="wa", provider_user_id=wa_user_id, display_name=None, phone=None)
    account_id = _extract_account_id_from_upsert(up)

    if not account_id:
        return jsonify({
            "ok": False,
            "error": "account_upsert_failed",
            "root_cause": up.get("root_cause") or up.get("error") or "upsert_account returned no account_id",
            "fix": up.get("fix") or "Fix accounts_service.upsert_account to always return accounts.account_id.",
            "details": {"provider": "wa", "provider_user_id": wa_user_id},
        }), 500

    # linking flow
    link_result = _maybe_link_from_message("whatsapp", text, wa_user_id)
    if link_result and link_result.get("ok"):
        send_whatsapp_text(wa_user_id, "✅ Linked successfully. You can now use the service.")
        return jsonify({"ok": True, "linked": True, "link": link_result}), 200

    # normal question flow (STRICT account_id)
    resp = ask_guarded({"account_id": account_id, "provider": "wa", "provider_user_id": wa_user_id, "question": text})

    answer = ""
    if isinstance(resp, dict):
        answer = (resp.get("answer") or resp.get("message") or "").strip()
    if answer:
        send_whatsapp_text(wa_user_id, answer)

    return jsonify(resp), 200


# -------------------------
# Telegram inbound
# -------------------------
@bp.post("/inbound/telegram")
def telegram_inbound():
    body = _json_body()
    tg_chat_id, tg_user_id, text = _extract_telegram_text(body)

    if not tg_chat_id or not tg_user_id:
        return jsonify({"ok": True, "ignored": True, "reason": "no_sender"}), 200

    if not text:
        return jsonify({"ok": True, "ignored": True, "reason": "no_text"}), 200

    up = upsert_account(provider="tg", provider_user_id=tg_user_id, display_name=None, phone=None)
    account_id = _extract_account_id_from_upsert(up)

    if not account_id:
        return jsonify({
            "ok": False,
            "error": "account_upsert_failed",
            "root_cause": up.get("root_cause") or up.get("error") or "upsert_account returned no account_id",
            "fix": up.get("fix") or "Fix accounts_service.upsert_account to always return accounts.account_id.",
            "details": {"provider": "tg", "provider_user_id": tg_user_id},
        }), 500

    # linking flow
    link_result = _maybe_link_from_message("telegram", text, tg_user_id)
    if link_result and link_result.get("ok"):
        send_telegram_text(tg_chat_id, "✅ Linked successfully. You can now use the service.")
        return jsonify({"ok": True, "linked": True, "link": link_result}), 200

    resp = ask_guarded({"account_id": account_id, "provider": "tg", "provider_user_id": tg_user_id, "question": text})

    answer = ""
    if isinstance(resp, dict):
        answer = (resp.get("answer") or resp.get("message") or "").strip()
    if answer:
        send_telegram_text(tg_chat_id, answer)

    return jsonify(resp), 200
