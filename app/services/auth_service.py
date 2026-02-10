# app/services/auth_service.py
from typing import Any, Dict
from flask import request
from app.core.supabase_client import supabase


def get_bearer_token() -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip() or None


def get_current_user() -> Dict[str, Any] | None:
    """
    Validates Supabase JWT by asking Supabase Auth using service role.
    Requires Authorization: Bearer <access_token>
    """
    token = get_bearer_token()
    if not token:
        return None

    sb = supabase()
    try:
        # supabase-py supports auth.get_user(token)
        res = sb.auth.get_user(token)
        # Depending on supabase-py version, object shape may differ
        user = getattr(res, "user", None) or res.get("user") if isinstance(res, dict) else None
        if not user:
            return None
        return user if isinstance(user, dict) else user.model_dump()
    except Exception:
        return None
