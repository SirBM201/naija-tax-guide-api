# app/middleware/web_auth.py
from __future__ import annotations

from functools import wraps
from typing import Callable, Any, Tuple, Optional, Dict

from flask import request, jsonify

from app.services.web_auth_service import get_account_id_from_request


def require_web_auth(fn: Callable[..., Any]):
    """
    Single source of truth auth guard:
      - Uses get_account_id_from_request(request)
      - On success: attaches request.account_id
      - On failure: returns 401 with debug
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        account_id, debug = get_account_id_from_request(request)
        if not account_id:
            return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

        # attach for downstream handlers (optional convenience)
        setattr(request, "account_id", account_id)
        setattr(request, "auth_debug", debug)

        return fn(*args, **kwargs)

    return wrapper
