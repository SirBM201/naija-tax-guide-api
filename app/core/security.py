# app/core/security.py
from __future__ import annotations

from functools import wraps
from flask import request, jsonify

try:
    from app.core.config import ADMIN_API_KEY
except Exception:
    ADMIN_API_KEY = ""


def _extract_key() -> str:
    key = (request.headers.get("X-Admin-Key") or "").strip()
    if key:
        return key
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""


def require_admin_key():
    """
    Guard-style helper:
      - returns (json, status) if blocked
      - returns None if allowed
    """
    if not ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "admin_key_not_configured"}), 503

    key = _extract_key()
    if key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "invalid_admin_key"}), 401

    return None


def admin_required(fn):
    """
    Decorator-style helper (optional).
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        blocked = require_admin_key()
        if blocked is not None:
            return blocked
        return fn(*args, **kwargs)
    return wrapper
