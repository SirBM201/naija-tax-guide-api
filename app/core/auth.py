# app/core/auth.py
from __future__ import annotations

from functools import wraps
from datetime import datetime, timezone
from flask import request, jsonify, g

from app.core.supabase_client import supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_bearer_token() -> str | None:
    raw = request.headers.get("Authorization", "") or ""
    raw = raw.strip()
    if not raw:
        return None

    # Accept:
    #   "Bearer <token>"
    # and also (fallback) "<token>"
    if raw.lower().startswith("bearer "):
        return raw.split(" ", 1)[1].strip() or None
    return raw  # fallback


def _validate_web_token(token: str) -> str | None:
    """
    Returns account_id if token is valid, else None.
    """
    if not token:
        return None

    res = (
        supabase.table("web_auth_tokens")
        .select("account_id, expires_at, revoked_at")
        .eq("token", token)
        .limit(1)
        .execute()
    )

    rows = getattr(res, "data", None) or []
    if not rows:
        return None

    row = rows[0]
    if row.get("revoked_at"):
        return None

    exp_raw = row.get("expires_at")
    if not exp_raw:
        return None

    try:
        exp = datetime.fromisoformat(exp_raw.replace("Z", "+00:00"))
    except Exception:
        return None

    if exp <= _now_utc():
        return None

    return row.get("account_id")


def require_auth_plus(fn):
    """
    Token auth for web endpoints.

    Header:
      Authorization: Bearer <token>

    Validates against public.web_auth_tokens table.
    Sets:
      g.account_id
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = _parse_bearer_token()
        account_id = _validate_web_token(token or "")

        if not account_id:
            return jsonify({"ok": False, "error": "invalid_token"}), 401

        g.account_id = account_id
        return fn(*args, **kwargs)

    return wrapper
