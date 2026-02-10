# app/routes/cron.py
from flask import Blueprint, jsonify
from ..core.security import require_admin_key
from ..services.subscriptions_service import expire_overdue_subscriptions
from ..core.supabase_client import supabase

bp = Blueprint("cron", __name__)

@bp.post("/internal/cron/expire-subscriptions")
def expire_subscriptions():
    guard = require_admin_key()
    if guard is not None:
        return guard
    try:
        result = expire_overdue_subscriptions(batch_limit=1000)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.post("/internal/cron/expire-credits")
def expire_credits():
    guard = require_admin_key()
    if guard is not None:
        return guard
    try:
        res = supabase().rpc("expire_ai_credits", {}).execute()
        data = res.data
        if isinstance(data, list):
            data = data[0] if data else {}
        return jsonify({"ok": True, "result": data}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
