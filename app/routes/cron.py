# app/routes/cron.py
from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.security import require_admin_key
from app.core.supabase_client import supabase  # should be the client object (not supabase())

bp = Blueprint("cron", __name__)


def _get_int(payload: Dict[str, Any], key: str, default: int) -> int:
    try:
        v = payload.get(key, default)
        v = int(v)
        return v if v > 0 else default
    except Exception:
        return default


def _rpc_single_dict(res) -> Dict[str, Any]:
    data = getattr(res, "data", None)
    if isinstance(data, list):
        return data[0] if data else {}
    if isinstance(data, dict):
        return data
    return {}


# ----------------------------
# Subscriptions: expire overdue
# ----------------------------
@bp.post("/internal/cron/expire-subscriptions")
@bp.post("/api/internal/cron/expire-subscriptions")
def expire_subscriptions():
    guard = require_admin_key()
    if guard is not None:
        return guard

    payload = request.get_json(silent=True) or {}
    batch_limit = _get_int(payload, "batch_limit", 1000)

    try:
        # SQL RPC (recommended) — avoids missing Python symbols/imports
        res = supabase.rpc("expire_overdue_subscriptions", {"batch_limit": batch_limit}).execute()
        out = _rpc_single_dict(res)
        return jsonify({"ok": True, "batch_limit": batch_limit, "result": out}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ----------------------------
# Credits: expire AI credits
# ----------------------------
@bp.post("/internal/cron/expire-credits")
@bp.post("/api/internal/cron/expire-credits")
def expire_credits():
    guard = require_admin_key()
    if guard is not None:
        return guard

    payload = request.get_json(silent=True) or {}
    batch_limit = _get_int(payload, "batch_limit", 5000)

    try:
        # If your RPC doesn't accept batch_limit, remove the arg below.
        res = supabase.rpc("expire_ai_credits", {"batch_limit": batch_limit}).execute()
        out = _rpc_single_dict(res)
        return jsonify({"ok": True, "batch_limit": batch_limit, "result": out}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
