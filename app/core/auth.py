# app/core/auth.py
import os
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple

from flask import request, jsonify, g

from app.core.supabase_client import supabase


# ------------------------------------------------------------
# Config helpers
# ------------------------------------------------------------
def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()


WEB_TOKEN_TABLE = _env("WEB_TOKEN_TABLE", "web_sessions")
WEB_TOKEN_COL_TOKEN = _env("WEB_TOKEN_COL_TOKEN", "token_hash")
WEB_TOKEN_COL_ACCOUNT_ID = _env("WEB_TOKEN_COL_ACCOUNT_ID", "account_id")
WEB_TOKEN_COL_EXPIRES_AT = _env("WEB_TOKEN_COL_EXPIRES_AT", "expires_at")
WEB_TOKEN_COL_REVOKED_AT = _env("WEB_TOKEN_COL_REVOKED_AT", "revoked_at")

# MUST match the value used when you created token_hash in verify-otp
WEB_TOKEN_PEPPER = _env("WEB_TOKEN_PEPPER", "")


# ------------------------------------------------------------
# Types
# ------------------------------------------------------------
@dataclass
class AuthContext:
    ok: bool
    account_id: Optional[str] = None
    token: Optional[str] = None
    error: Optional[str] = None


# ------------------------------------------------------------
# Core logic
# ------------------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def _hash_token(raw_token: str) -> str:
    """
    Hash token exactly the same way you did during verify-otp.
    If your verify-otp used sha256(token + pepper), this must match.
    """
    if not raw_token:
        return ""
    if not WEB_TOKEN_PEPPER:
        # If pepper is empty, your hashing will not match production tokens.
        # Better to fail explicitly.
        raise RuntimeError("WEB_TOKEN_PEPPER is not set")
    payload = (raw_token + WEB_TOKEN_PEPPER).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _extract_bearer_token() -> Optional[str]:
    """
    Accepts:
      Authorization: Bearer <token>
    """
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip() or None
    return None


def _load_session_from_db(token_hash: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Returns (row, error_message)
    """
    try:
        res = (
            supabase.table(WEB_TOKEN_TABLE)
            .select(f"{WEB_TOKEN_COL_ACCOUNT_ID},{WEB_TOKEN_COL_EXPIRES_AT},{WEB_TOKEN_COL_REVOKED_AT}")
            .eq(WEB_TOKEN_COL_TOKEN, token_hash)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None, "Invalid token"
        return rows[0], None
    except Exception as e:
        return None, f"Auth lookup failed: {e}"


def validate_request_auth() -> AuthContext:
    raw = _extract_bearer_token()
    if not raw:
        return AuthContext(ok=False, error="Missing bearer token")

    try:
        token_hash = _hash_token(raw)
    except Exception as e:
        return AuthContext(ok=False, error=str(e))

    row, err = _load_session_from_db(token_hash)
    if err:
        return AuthContext(ok=False, error=err)

    revoked_at = _parse_iso(row.get(WEB_TOKEN_COL_REVOKED_AT))
    if revoked_at:
        return AuthContext(ok=False, error="Token revoked")

    expires_at = _parse_iso(row.get(WEB_TOKEN_COL_EXPIRES_AT))
    if expires_at and expires_at <= _now_utc():
        return AuthContext(ok=False, error="Token expired")

    account_id = row.get(WEB_TOKEN_COL_ACCOUNT_ID)
    if not account_id:
        return AuthContext(ok=False, error="Token missing account_id")

    return AuthContext(ok=True, account_id=account_id, token=raw)


# ------------------------------------------------------------
# Decorators
# ------------------------------------------------------------
def require_auth(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ctx = validate_request_auth()
        if not ctx.ok:
            return jsonify({"ok": False, "error": "Unauthorized", "detail": ctx.error}), 401
        g.account_id = ctx.account_id
        g.token = ctx.token
        return fn(*args, **kwargs)

    return wrapper


def require_auth_plus(fn: Callable) -> Callable:
    """
    Same as require_auth, but leaves room to attach subscription/credits later.
    For now it simply authenticates and sets g.account_id.
    """
    return require_auth(fn)
