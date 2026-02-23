# app/routes/_debug.py
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.services.subscription_status_service import get_subscription_status

bp = Blueprint("_debug", __name__)

ADMIN_KEY = (os.getenv("ADMIN_KEY", "") or "").strip()


def _admin_key_configured() -> bool:
    return bool(ADMIN_KEY)


def _is_admin(req) -> bool:
    if not ADMIN_KEY:
        return False
    key = (req.headers.get("X-Admin-Key", "") or "").strip()
    return bool(key) and key == ADMIN_KEY


def _forbid():
    got = bool((request.headers.get("X-Admin-Key", "") or "").strip())
    return (
        jsonify(
            {
                "ok": False,
                "error": "forbidden",
                "message": "Admin key required." if not got else "Admin key invalid.",
            }
        ),
        403,
    )


@bp.get("/_debug/config")
def debug_config():
    if not _admin_key_configured():
        return jsonify({"ok": False, "error": "admin_key_not_configured"}), 500
    if not _is_admin(request):
        return _forbid()

    safe_env = {
        "env": (os.getenv("ENV", "") or "prod").strip(),
        "api_prefix": (os.getenv("API_PREFIX", "") or "/api").strip(),
        "cors_origins_set": bool((os.getenv("CORS_ORIGINS", "") or "").strip()),
        "cookie_auth_enabled": (os.getenv("COOKIE_AUTH_ENABLED", "") or "").strip(),
        "web_auth_enabled": (os.getenv("WEB_AUTH_ENABLED", "") or "").strip(),
        "subscriptions_table": (os.getenv("SUBSCRIPTIONS_TABLE", "") or "subscriptions").strip(),
        "admin_key_configured": True,
    }
    return jsonify({"ok": True, "safe_env": safe_env}), 200


@bp.get("/_debug/subscription")
def debug_subscription():
    if not _admin_key_configured():
        return jsonify({"ok": False, "error": "admin_key_not_configured"}), 500
    if not _is_admin(request):
        return _forbid()

    account_id = (request.args.get("account_id", "") or "").strip()
    if not account_id:
        return jsonify({"ok": False, "error": "missing_account_id"}), 400

    status = get_subscription_status(account_id)
    return jsonify({"ok": True, "account_id": account_id, "computed_status": status}), 200
