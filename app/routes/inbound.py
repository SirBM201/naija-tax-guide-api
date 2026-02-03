# app/routes/inbound.py
from flask import Blueprint, request, jsonify

from ..services.accounts_service import upsert_account
from ..services.ask_service import ask_guarded
from ..services.db import supabase_admin

bp = Blueprint("inbound", __name__)

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def _consume_link(provider: str, code: str):
    """
    Call RPC consume_link_token(provider, code)
    Uses service role (admin) because this is server-side.
    """
    provider = (provider or "").strip()
    code = (code or "").strip()
    if not provider or not code:
        return None

    # IMPORTANT: supabase_admin is a function (returns client)
    db = supabase_admin()
    res = db.rpc(
        "consume_link_token",
        {"p_provider": provider, "p_code": code},
    ).execute()
    return res.data[0] if getattr(res, "data", None) else None


def _maybe_link_from_message(provider: str, text: str):
    """
    Detect LINK <code> command.
    """
    txt = (text or "").strip()
    if not txt:
        return None

    low = txt.lower()
    if not low.startswith("link "):
        return None

    code = txt[5:].strip()  # everything after "link "
    if not code:
        return None

    return _consume_link(provider, code)


def _json_body():
    """
    Safe JSON getter: avoids crashing gunicorn on empty/non-json payloads.
    """
    return request.get_json(silent=True) or {}


# -------------------------------------------------
# WhatsApp inbound
# -------------------------------------------------

@bp.post("/inbound/whatsapp")
def whatsapp_inbound():
    body = _json_body()

    # WhatsApp webhook can send statuses/other events where "messages" is absent
    try:
        entry = body.get("entry", [])[0]
        change = entry.get("changes", [])[0]
        value = change.get("value", {})
        messages = value.get("messages", [])
        if not messages:
            # likely status update / delivery receipt, ignore gracefully
            return jsonify({"ok": True, "ignored": True, "reason": "no_messages"}), 200

        msg = messages[0]
        wa_user_id = str(msg.get("from") or "").strip()
        text = (msg.get("text", {}) or {}).get("body", "") or ""
    except Exception:
        return jsonify({"ok": False, "error": "invalid_whatsapp_payload"}), 400

    if not wa_user_id:
        return jsonify({"ok": False, "error": "missing_sender"}), 400

    # Ensure account exists
    account = upsert_account(
        provider="wa",
        provider_user_id=wa_user_id,
    )

    # Try linking
    link_result = _maybe_link_from_message("wa", text)
    if link_result:
        return jsonify({"ok": True, "linked": True}), 200

    # Normal question flow
    resp = ask_guarded(
        {
            "account_id": account["id"],
            "question": text,
        }
    )
    return jsonify(resp), 200


# -------------------------------------------------
# Telegram inbound
# -------------------------------------------------

@bp.post("/inbound/telegram")
def telegram_inbound():
    body = _json_body()

    # Telegram updates can be: message, edited_message, callback_query, etc.
    msg = body.get("message") or body.get("edited_message") or {}
    if not msg:
        # not a chat message update, ignore gracefully
        return jsonify({"ok": True, "ignored": True, "reason": "no_message"}), 200

    tg_from = msg.get("from", {}) or {}
    tg_user_id = str(tg_from.get("id") or "").strip()
    text = (msg.get("text") or "").strip()

    if not tg_user_id:
        return jsonify({"ok": False, "error": "missing_sender"}), 400

    # Ensure account exists
    account = upsert_account(
        provider="telegram",
        provider_user_id=tg_user_id,
    )

    # Try linking
    link_result = _maybe_link_from_message("telegram", text)
    if link_result:
        return jsonify({"ok": True, "linked": True}), 200

    # Normal question flow
    resp = ask_guarded(
        {
            "account_id": account["id"],
            "question": text,
        }
    )
    return jsonify(resp), 200
