# app/core/security.py
from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional, Tuple

from flask import request, jsonify

from app.core.config import ADMIN_API_KEY


def _extract_admin_key() -> str:
    """
    Accept admin key from:
      - X-Admin-Key: <key>
      - Authorization: Bearer <key>
    """
    key = (request.headers.get("X-Admin-Key") or "").strip()
    if key:
        return key

    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()

    return ""


def _check_admin() -> Optional[Tuple[Any, int]]:
    """
    Returns:
      None -> authorized
      (json_response, status_code) -> not authorized / not configured
    """
    if not ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "admin_key_not_configured"}), 503

    key = _extract_admin_key()
    if key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "invalid_admin_key"}), 401

    return None


def require_admin_key(fn: Callable) -> Callable:
    """
    Decorator for admin-only routes.

    Usage:
      @bp.post("/something")
      @require_admin_key
      def handler():
          ...
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        guard = _check_admin()
        if guard is not None:
            return guard
        return fn(*args, **kwargs)

    return wrapper
