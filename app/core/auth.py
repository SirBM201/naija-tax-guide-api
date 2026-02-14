# app/core/auth.py
from __future__ import annotations

from functools import wraps
from typing import Callable, Optional, Any, Dict, Tuple

from flask import request, jsonify, g

from ..services.web_tokens_service import (
    validate_token,
    extract_bearer_token,
)


def require_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
    """
    Auth guard for protected routes.

    Accepts token from:
      - Authorization: Bearer <token>
      - X-Auth-Token: <token> (fallback)

    On success:
      g.account_id = <uuid>
      g.auth_token = <token>
      g.token_row = <dict row from web_tokens>
    """
    @wraps(fn)
    def _wrapped(*args: Any, **kwargs: Any):
        token = extract_bearer_token(request)
        if not token:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        ok, payload, err = validate_token(token)
        if not ok:
            # err is safe + generic
            return jsonify({"ok": False, "error": err or "Unauthorized"}), 401

        g.account_id = payload["account_id"]
        g.auth_token = token
        g.token_row = payload.get("token_row") or {}

        return fn(*args, **kwargs)

    return _wrapped
