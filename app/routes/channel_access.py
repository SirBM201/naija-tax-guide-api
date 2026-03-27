from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.channel_identity_service import (
    ensure_account_for_channel_identity,
    initialize_channel_subscription_context,
)

bp = Blueprint("channel_access", __name__)


def _clean(value):
    return str(value or "").strip()


@bp.post("/channel/ensure-account")
def ensure_channel_account():
    body = request.get_json(silent=True) or {}

    channel_type = _clean(body.get("channel_type"))
    provider_user_id = _clean(body.get("provider_user_id"))
    display_name = _clean(body.get("display_name")) or None
    referral_code = _clean(body.get("referral_code")) or None

    if channel_type not in {"whatsapp", "telegram", "web"}:
        return jsonify(
            {
                "ok": False,
                "error": "invalid_channel_type",
                "allowed": ["whatsapp", "telegram", "web"],
            }
        ), 400

    if not provider_user_id:
        return jsonify(
            {
                "ok": False,
                "error": "provider_user_id_required",
            }
        ), 400

    result = ensure_account_for_channel_identity(
        channel_type=channel_type,
        provider_user_id=provider_user_id,
        display_name=display_name,
        referral_code=referral_code,
    )
    return jsonify(result), 200


@bp.post("/channel/subscription/initialize")
def initialize_channel_subscription():
    body = request.get_json(silent=True) or {}

    account_id = _clean(body.get("account_id"))
    channel_type = _clean(body.get("channel_type"))
    provider_user_id = _clean(body.get("provider_user_id"))
    plan_code = _clean(body.get("plan_code"))

    if not account_id:
        return jsonify({"ok": False, "error": "account_id_required"}), 400
    if channel_type not in {"whatsapp", "telegram", "web"}:
        return jsonify({"ok": False, "error": "invalid_channel_type"}), 400
    if not provider_user_id:
        return jsonify({"ok": False, "error": "provider_user_id_required"}), 400
    if not plan_code:
        return jsonify({"ok": False, "error": "plan_code_required"}), 400

    result = initialize_channel_subscription_context(
        account_id=account_id,
        channel_type=channel_type,
        provider_user_id=provider_user_id,
        plan_code=plan_code,
    )
    return jsonify(result), 200
