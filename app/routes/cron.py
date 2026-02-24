# app/routes/cron.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.core.security import require_admin_key
from app.core.supabase_client import supabase

# IMPORTANT:
# Your system no longer depends on expire_overdue_subscriptions()
# (it was removed when we migrated to RPC activation model).
#
# So cron expiration must run via SQL / RPC instead.

bp = Blueprint("cron", __name__)


# ---------------------------------------------------------
# Helper: normalize supabase RPC response
# ---------------------------------------------------------
def _normalize_rpc(res):
    try:
        data = getattr(res, "data", None)
        if isinstance(data, list):
            return data[0] if data else {}
        return data or {}
    except Exception:
        return {}


# ---------------------------------------------------------
# CRON 1 — Expire Subscriptions
# ---------------------------------------------------------
@bp.post("/internal/cron/expire-subscriptions")
def expire_subscriptions():
    """
    Expires subscriptions whose current_period_end < now().
    Requires RPC function: expire_overdue_subscriptions()
    """

    guard = require_admin_key()
    if guard is not None:
        return guard

    try:
        res = supabase().rpc(
            "expire_overdue_subscriptions",
            {"batch_limit": 1000},
        ).execute()

        data = _normalize_rpc(res)

        return jsonify({
            "ok": True,
            "job": "expire_subscriptions",
            "result": data
        }), 200

    except Exception as e:
        return jsonify({
            "ok": False,
            "job": "expire_subscriptions",
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# CRON 2 — Expire AI Credits
# ---------------------------------------------------------
@bp.post("/internal/cron/expire-credits")
def expire_credits():
    """
    Runs credit expiration RPC.
    Requires RPC function: expire_ai_credits()
    """

    guard = require_admin_key()
    if guard is not None:
        return guard

    try:
        res = supabase().rpc(
            "expire_ai_credits",
            {}
        ).execute()

        data = _normalize_rpc(res)

        return jsonify({
            "ok": True,
            "job": "expire_credits",
            "result": data
        }), 200

    except Exception as e:
        return jsonify({
            "ok": False,
            "job": "expire_credits",
            "error": str(e)
        }), 500


# ---------------------------------------------------------
# Health Probe (optional but useful)
# ---------------------------------------------------------
@bp.get("/internal/cron/health")
def cron_health():
    return jsonify({
        "ok": True,
        "cron_routes": [
            "/internal/cron/expire-subscriptions",
            "/internal/cron/expire-credits"
        ]
    }), 200
