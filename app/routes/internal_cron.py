from __future__ import annotations

from flask import Blueprint, request, jsonify, current_app
from app.core.supabase_client import supabase

bp = Blueprint("internal_cron", __name__)


# ---------------------------------------------------------
# Helper: Admin key validation
# ---------------------------------------------------------
def _check_admin():
    admin_key = request.headers.get("X-Admin-Key")
    expected = current_app.config.get("ADMIN_KEY")

    if not admin_key or admin_key != expected:
        return False
    return True


# ---------------------------------------------------------
# Expire Subscriptions
# ---------------------------------------------------------
@bp.post("/internal/cron/expire-subscriptions")
def expire_subscriptions():

    if not _check_admin():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    batch_limit = body.get("batch_limit", 100)

    try:
        res = supabase.rpc(
            "expire_subscriptions",
            {"batch_limit": batch_limit}
        ).execute()

        return jsonify({
            "ok": True,
            "rpc": "expire_subscriptions",
            "result": res.data
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Expire AI Credits
# ---------------------------------------------------------
@bp.post("/internal/cron/expire-credits")
def expire_credits():

    if not _check_admin():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    batch_limit = body.get("batch_limit", 100)

    try:
        res = supabase.rpc(
            "expire_ai_credits",
            {"batch_limit": batch_limit}
        ).execute()

        return jsonify({
            "ok": True,
            "rpc": "expire_ai_credits",
            "result": res.data
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e)
        }), 500
