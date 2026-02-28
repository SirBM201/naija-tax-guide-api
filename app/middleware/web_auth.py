# app/middleware/web_auth.py
from __future__ import annotations

from functools import wraps
from typing import Any, Dict

from flask import request, jsonify, g

from app.services.web_auth_service import get_account_id_from_request
from ..core.supabase_client import supabase

# ... keep _load_subscription and _load_credits as-is ...

def require_web_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return ("", 204)

        account_id, debug = get_account_id_from_request(request)
        if not account_id:
            return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

        g.account_id = str(account_id).strip()
        g.subscription = _load_subscription(g.account_id)
        g.credits = _load_credits(g.account_id)

        return fn(*args, **kwargs)

    return wrapper
