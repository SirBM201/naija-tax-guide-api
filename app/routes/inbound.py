from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.accounts_service import upsert_account
from app.services.ask_service import ask_guarded
from app.services.channel_linking_service import consume_and_link, extract_code
from app.services.outbound_service import send_telegram_text, send_whatsapp_text

bp = Blueprint("inbound", __name__)


def _json_body() -> dict:
    return request.get_json(silent=True) or {}


def _maybe_link_from_message(channel: str, text: str, provider_user_id: str):
    code = extract_code(text or "")
    if not code:
        return None

    provider = "tg" if channel == "telegram" else "wa"
    return consume_and_link(
        provider=provider,
        code=code,
        provider_user_id=provider_user_id,
        display_name=None,
        phone=None,
    )


def _extract_whatsapp_text(body: dict):
    try:
        entry = (body.get("entry") or [None])[0] or {}
        changes = (entry.get("changes") or [None])[0] or {}
        value = changes.get("value") or {}

        messages = value.get("messages") or []
        if not messages:
            return (None, None)

        msg = messages[0] or {}
        wa_user_id = str(msg.get("from") or "").strip()
        if not wa_user_id:
            return (None, None)

        msg_type = str(msg.get("type") or "").strip().lower()
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

    text = str(msg.get("text") or "").strip()

    if not tg_chat_id or not tg_user_id or not text:
        return (tg_chat_id or None, tg_user_id or None, None)

    return (tg_chat_id, tg_user_id, text)


def _extract_account_id_from_upsert(result: dict) -> str | None:
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


@bp.post("/inbound/whatsapp")
def whatsapp_inbound():
    body = _json_body()
    wa_user_id, text = _extract_whatsapp_text(body)

    if not wa_user_id:
        return jsonify({"ok": True, "ignored": True, "reason": "no_sender_or_status"}), 200

    if not text:
        return jsonify({"ok": True, "ignored": True, "reason": "no_text"}), 200

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

    link_result = _maybe_link_from_message("whatsapp", text, wa_user_id)
    if link_result and link_result.get("ok"):
        send_whatsapp_text(wa_user_id, "✅ Linked successfully. You can now use the service.")
        return jsonify({"ok": True, "linked": True, "link": link_result}), 200

    resp = ask_guarded(
        account_id=account_id,
        question=text,
        lang="en",
        channel="whatsapp",
    )

    answer = ""
    if isinstance(resp, dict):
        answer = str(resp.get("answer") or resp.get("message") or "").strip()
    if answer:
        send_whatsapp_text(wa_user_id, answer)

    return jsonify(resp), 200


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

    link_result = _maybe_link_from_message("telegram", text, tg_user_id)
    if link_result and link_result.get("ok"):
        send_telegram_text(tg_chat_id, "✅ Linked successfully. You can now use the service.")
        return jsonify({"ok": True, "linked": True, "link": link_result}), 200

    resp = ask_guarded(
        account_id=account_id,
        question=text,
        lang="en",
        channel="telegram",
    )

    answer = ""
    if isinstance(resp, dict):
        answer = str(resp.get("answer") or resp.get("message") or "").strip()
    if answer:
        send_telegram_text(tg_chat_id, answer)

    return jsonify(resp), 200
