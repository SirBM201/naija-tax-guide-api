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
    res = supabase_admin.rpc(
        "consume_link_token",
        {"p_provider": provider, "p_code": code},
    ).execute()
    return res.data[0] if res.data else None


def _maybe_link_from_message(provider: str, text: str):
    """
    Detect LINK <code> command.
    """
    text = (text or "").strip().lower()
    if not text.startswith("link "):
        return None

    code = text.replace("link", "").strip()
    if not code:
        return None

    return _consume_link(provider, code)


# -------------------------------------------------
# WhatsApp inbound
# -------------------------------------------------

@bp.post("/inbound/whatsapp")
def whatsapp_inbound():
    body = request.get_json(force=True)

    # Extract sender + message (simplified)
    entry = body["entry"][0]["changes"][0]["value"]
    msg = entry["messages"][0]

    wa_user_id = msg["from"]
    text = msg.get("text", {}).get("body", "")

    # Ensure account exists
    account = upsert_account(
        provider="wa",
        provider_user_id=wa_user_id,
    )

    # Try linking
    link_result = _maybe_link_from_message("wa", text)
    if link_result:
        return jsonify({"ok": True, "linked": True})

    # Normal question flow
    resp = ask_guarded({
        "account_id": account["id"],
        "question": text,
    })
    return jsonify(resp)


# -------------------------------------------------
# Telegram inbound
# -------------------------------------------------

@bp.post("/inbound/telegram")
def telegram_inbound():
    body = request.get_json(force=True)

    msg = body.get("message", {})
    tg_user_id = str(msg.get("from", {}).get("id"))
    text = msg.get("text", "")

    account = upsert_account(
        provider="telegram",
        provider_user_id=tg_user_id,
    )

    link_result = _maybe_link_from_message("telegram", text)
    if link_result:
        return jsonify({"ok": True, "linked": True})

    resp = ask_guarded({
        "account_id": account["id"],
        "question": text,
    })
    return jsonify(resp)
