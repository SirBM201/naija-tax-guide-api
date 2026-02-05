# app/routes/accounts.py
from flask import Blueprint, jsonify, request
from ..services.accounts_service import upsert_account

bp = Blueprint("accounts", __name__)

@bp.post("/accounts")
def create_or_get_account():
    """
    Create or find an account by provider identity.
    Body:
      {
        "provider": "whatsapp" | "telegram",
        "provider_user_id": "<string>",
        "display_name": "<optional>",
        "phone": "<optional>"
      }
    """
    body = request.get_json(silent=True) or {}

    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if provider not in ("whatsapp", "telegram"):
        return jsonify({"ok": False, "error": "provider must be whatsapp or telegram"}), 400
    if not provider_user_id:
        return jsonify({"ok": False, "error": "provider_user_id is required"}), 400

    account = upsert_account(
        provider=provider,
        provider_user_id=provider_user_id,
        display_name=(body.get("display_name") or "").strip() or None,
        phone=(body.get("phone") or "").strip() or None,
    )

    return jsonify({"ok": True, "account": account}), 200
