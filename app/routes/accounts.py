from flask import Blueprint, jsonify, request
from app.services.accounts_service import upsert_account

bp = Blueprint("accounts", __name__)


@bp.post("/accounts")
def create_or_get_account():
    """
    Create or update an account row by provider identity.

    Body:
      {
        "provider": "wa" | "tg",
        "provider_user_id": "<string>",
        "display_name": "<optional>",
        "phone": "<optional>",
        "auth_user_id": "<optional uuid>"
      }

    Notes:
    - If auth_user_id is provided, it will link provider_user_id to that auth user.
    - If auth_user_id is omitted, it will upsert without linking (legacy behavior).
    """
    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()
    display_name = body.get("display_name")
    phone = body.get("phone")
    auth_user_id = (body.get("auth_user_id") or "").strip() or None

    if provider not in ("wa", "tg"):
        return jsonify({"ok": False, "error": "provider must be wa or tg"}), 400
    if not provider_user_id:
        return jsonify({"ok": False, "error": "provider_user_id required"}), 400

    try:
        result = upsert_account(
            provider=provider,
            provider_user_id=provider_user_id,
            display_name=display_name,
            phone=phone,
            auth_user_id=auth_user_id,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed: {str(e)}"}), 500

    status = 200 if result.get("ok") else 400
    return jsonify(result), status
