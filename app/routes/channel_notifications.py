from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.channel_post_payment_service import (
    notify_channel_payment_success,
)

bp = Blueprint("channel_notifications", __name__)


def _clean(value):
    return str(value or "").strip()


@bp.post("/channel/payment/notify-success")
def channel_payment_notify_success():
    try:
        body = request.get_json(silent=True) or {}

        account_id = _clean(body.get("account_id"))
        channel_type = _clean(body.get("channel_type"))
        provider_user_id = _clean(body.get("provider_user_id")) or None
        plan_code = _clean(body.get("plan_code"))

        if not account_id:
            return jsonify(
                {
                    "ok": False,
                    "error": "account_id_required",
                    "fix": "Pass account_id in the JSON body.",
                }
            ), 400

        if channel_type not in {"whatsapp", "telegram"}:
            return jsonify(
                {
                    "ok": False,
                    "error": "invalid_channel_type",
                    "fix": "Use whatsapp or telegram for channel success notification.",
                    "allowed": ["whatsapp", "telegram"],
                }
            ), 400

        if not plan_code:
            return jsonify(
                {
                    "ok": False,
                    "error": "plan_code_required",
                    "fix": "Pass the active plan_code in the JSON body.",
                }
            ), 400

        result = notify_channel_payment_success(
            account_id=account_id,
            channel_type=channel_type,
            provider_user_id=provider_user_id,
            plan_code=plan_code,
        )

        if not result.get("ok"):
            return jsonify(result), 400

        return jsonify(result), 200

    except Exception as e:
        return jsonify(
            {
                "ok": False,
                "error": "channel_payment_notify_success_failed",
                "where": "app.routes.channel_notifications.channel_payment_notify_success",
                "root_cause": repr(e),
                "fix": "Check channel_post_payment_service and request payload.",
            }
        ), 500
