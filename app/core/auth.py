# app/core/auth.py
from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from flask import jsonify, g, request

from app.services.web_tokens_service import extract_bearer_token, validate_token


def require_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def _wrapped(*args: Any, **kwargs: Any):
        token = extract_bearer_token(request)
        if not token:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        ok, payload, err = validate_token(token)
        if not ok:
            return jsonify({"ok": False, "error": err or "Unauthorized"}), 401

        g.account_id = payload["account_id"]
        g.auth_token = token
        g.token_row = payload.get("token_row") or {}
        return fn(*args, **kwargs)

    return _wrapped
