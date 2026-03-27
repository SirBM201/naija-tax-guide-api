from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.channel_identity_service import update_account_email

bp = Blueprint("channel_profile", __name__)


def _clean(value):
    return str(value or "").strip()


@bp.post("/channel/profile/update-email")
def channel_update_email():
    try:
        body = request.get_json(silent=True) or {}

        account_id = _clean(body.get("account_id"))
        email = _clean(body.get("email"))

        if not account_id:
            return jsonify(
                {
                    "ok": False,
                    "error": "account_id_required",
                    "fix": "Pass account_id in the JSON body.",
                }
            ), 400

        if not email:
            return jsonify(
                {
                    "ok": False,
                    "error": "email_required",
                    "fix": "Pass a valid email in the JSON body.",
                }
            ), 400

        result = update_account_email(account_id=account_id, email=email)

        if not result.get("ok"):
            return jsonify(result), 400

        return jsonify(result), 200

    except Exception as e:
        return jsonify(
            {
                "ok": False,
                "error": "channel_update_email_failed",
                "where": "app.routes.channel_profile.channel_update_email",
                "root_cause": repr(e),
                "fix": "Check update_account_email service path and request payload.",
            }
        ), 500
