from __future__ import annotations

from functools import wraps
from typing import Callable, Optional, Any

from flask import request, jsonify

from app.core.config import ADMIN_API_KEY


def _extract_admin_key() -> str:
    key = (request.headers.get("X-Admin-Key") or "").strip()
    if key:
        return key

    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    return ""


def _check_admin() -> Optional[tuple]:
    """
    Returns:
      None  -> OK (authorized)
      (json, status_code) -> error response
    """
    if not ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "admin_key_not_configured"}), 503

    key = _extract_admin_key()
    if key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "invalid_admin_key"}), 401

    return None


def require_admin_key(fn: Callable | None = None):
    """
    Supports BOTH usages:

    1) As decorator:
        @require_admin_key
        def route(): ...

    2) As inline guard:
        guard = require_admin_key()
        if guard: return guard
    """

    # ---------
    # Inline guard usage: require_admin_key()
    # ---------
    if fn is None:
        return _check_admin()

    # ---------
    # Decorator usage: @require_admin_key
    # ---------
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        guard = _check_admin()
        if guard is not None:
            return guard
        return fn(*args, **kwargs)

    return wrapper
