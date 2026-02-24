# app/routes/cron.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..core.security import require_admin_key
from ..services.subscriptions_service import expire_overdue_subscriptions
from ..core.supabase_client import supabase


bp = Blueprint("cron", __name__)


# ------------------------------------------------------------
# Expire Subscriptions
# ------------------------------------------------------------
@bp.post("/internal/cron/expire-subscriptions")
def expire_subscriptions():
    guard = require_admin_key()
    if guard is not None:
        return guard

    try:
        # Optional batch_limit from body (safe default)
        payload = request.get_json(silent=True) or {}
        batch_limit = payload.get("batch_limit", 1000)

        # Try calling with batch_limit (new style)
        try:
            result = expire_overdue_subscriptions(batch_limit=batch_limit)
        except TypeError:
            # Fallback if service does not support batch_limit
            result = expire_overdue_subscriptions()

        return jsonify({
            "ok": True,
            "job": "expire_subscriptions",
            "result": result,
        }), 200

    except Exception as e:
        return jsonify({
            "ok": False,
            "job": "expire_subscriptions",
            "error": str(e),
        }), 500


# ------------------------------------------------------------
# Expire AI Credits
# ------------------------------------------------------------
@bp.post("/internal/cron/expire-credits")
def expire_credits():
    guard = require_admin_key()
    if guard is not None:
        return guard

    try:
        # Call RPC directly (supabase is NOT callable)
        res = supabase.rpc("expire_ai_credits", {}).execute()

        data = getattr(res, "data", None)

        # Normalize response
        if isinstance(data, list):
            data = data[0] if data else {}

        return jsonify({
            "ok": True,
            "job": "expire_credits",
            "result": data,
        }), 200

    except Exception as e:
        return jsonify({
            "ok": False,
            "job": "expire_credits",
            "error": str(e),
        }), 500
