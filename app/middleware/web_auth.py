# app/middleware/web_auth.py
from __future__ import annotations

from functools import wraps
from flask import request, jsonify, g

from ..services.web_auth_tokens import verify_access_token

def require_web_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = (request.headers.get("Authorization") or "").strip()
        if not auth.lower().startswith("bearer "):
            return jsonify({"ok": False, "error": "Missing token"}), 401

        token = auth.split(" ", 1)[1].strip()
        payload = verify_access_token(token)
        if not payload or not payload.get("account_id"):
            return jsonify({"ok": False, "error": "Invalid or expired token"}), 401

        g.account_id = payload["account_id"]
        return fn(*args, **kwargs)
    return wrapper
