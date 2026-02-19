# app/core/security.py
from __future__ import annotations

from functools import wraps
from flask import request, jsonify

from .config import ADMIN_API_KEY


def _extract_key() -> str:
    key = (request.headers.get("X-Admin-Key") or "").strip()
    if key:
        return key

    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    return ""


def _check_admin() -> tuple | None:
    """
    Returns (json, status_code) if unauthorized, else None.
    """
    if not ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "admin_key_not_configured"}), 503

    key = _extract_key()
    if not key:
        return jsonify({"ok": False, "error": "missing_admin_key"}), 401

    if key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "invalid_admin_key"}), 401

    return None


def require_admin_key(fn=None):
    """
    Dual-mode admin protection:

    1) Decorator usage:
        @require_admin_key
        def my_route(): ...

    2) Inline guard usage inside a route:
        guard = require_admin_key()
        if guard is not None:
            return guard
    """
    # Inline guard mode
    if fn is None:
        return _check_admin()

    # Decorator mode
    @wraps(fn)
    def wrapper(*args, **kwargs):
        guard = _check_admin()
        if guard is not None:
            return guard
        return fn(*args, **kwargs)

    return wrapper
