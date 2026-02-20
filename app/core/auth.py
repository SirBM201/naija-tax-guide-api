# app/core/auth.py
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Optional, Tuple

from flask import g, request, jsonify

from app.core.config import WEB_AUTH_ENABLED, WEB_TOKEN_PEPPER, WEB_TOKEN_TABLE
from app.core.supabase_client import supabase


# -----------------------------
# Time / helpers
# -----------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        v = (value or "").replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _normalize_bearer(auth_header: str) -> str:
    """Extract raw token from Authorization: Bearer <token>."""
    if not auth_header:
        return ""
    v = auth_header.strip()
    if v.lower().startswith("bearer "):
        return v[7:].strip()
    return ""


def _token_hash(raw_token: str) -> str:
    """
    MUST match the hashing scheme used when creating sessions.

    token_hash = sha256(f"{WEB_TOKEN_PEPPER}:{raw_token}")
    """
    return _sha256_hex(f"{WEB_TOKEN_PEPPER}:{raw_token}")


def _sb():
    # supabase can be either a client instance OR a callable factory
    return supabase() if callable(supabase) else supabase


# -----------------------------
# Session validation
# -----------------------------

def validate_web_session(raw_token: str) -> Tuple[bool, Optional[str], str]:
    """
    Return: (ok, account_id, reason)
    """
    if not WEB_AUTH_ENABLED:
        return False, None, "web_auth_disabled"

    if not raw_token:
        return False, None, "missing_token"

    token_hash = _token_hash(raw_token)

    try:
        q = (
            _sb()
            .table(WEB_TOKEN_TABLE)
            .select("id, account_id, expires_at, revoked")
            .eq("token_hash", token_hash)
            .eq("revoked", False)
            .limit(1)
            .execute()
        )
        rows = (q.data or []) if hasattr(q, "data") else []
    except Exception:
        return False, None, "session_lookup_failed"

    if not rows:
        return False, None, "invalid_token"

    row = rows[0]
    account_id = row.get("account_id")

    exp = _parse_iso(row.get("expires_at") or "")
    if not exp or _now_utc() > exp:
        # revoke expired session best-effort
        try:
            _sb().table(WEB_TOKEN_TABLE).update({"revoked": True}).eq("id", row.get("id")).execute()
        except Exception:
            pass
        return False, None, "token_expired"

    return True, account_id, "ok"


def touch_session_best_effort(raw_token: str) -> None:
    """Best-effort: update last_seen_at without breaking requests."""
    if not raw_token:
        return
    try:
        token_hash = _token_hash(raw_token)
        _sb().table(WEB_TOKEN_TABLE).update(
            {"last_seen_at": _now_utc().isoformat().replace("+00:00", "Z")}
        ).eq("token_hash", token_hash).execute()
    except Exception:
        return


# Backward-friendly alias (some files may call touch_session())
def touch_session(raw_token: str) -> None:
    touch_session_best_effort(raw_token)


# -----------------------------
# Decorators
# -----------------------------

def require_auth_plus(fn: Callable) -> Callable:
    """
    Flask decorator: validates bearer token and sets:
      g.account_id
      g.web_token
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        raw_token = _normalize_bearer(auth)

        ok, account_id, reason = validate_web_session(raw_token)
        if not ok or not account_id:
            return jsonify({"ok": False, "error": reason}), 401

        g.web_token = raw_token
        g.account_id = account_id

        touch_session_best_effort(raw_token)

        return fn(*args, **kwargs)

    return wrapper


def require_web_auth(fn: Callable) -> Callable:
    """
    Compatibility decorator for modules that previously expected require_web_auth(ctx).
    This version acts as normal Flask decorator and passes ctx as first arg.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        raw_token = _normalize_bearer(auth)

        ok, account_id, reason = validate_web_session(raw_token)
        if not ok or not account_id:
            return jsonify({"ok": False, "error": reason}), 401

        ctx = {"account_id": account_id, "token": raw_token}
        g.web_token = raw_token
        g.account_id = account_id

        touch_session_best_effort(raw_token)

        return fn(ctx, *args, **kwargs)

    return wrapper
