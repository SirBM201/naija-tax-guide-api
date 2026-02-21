# app/core/auth.py
from __future__ import annotations

import hashlib
import os
import traceback
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Optional, Dict

from flask import g, jsonify, request

from app.core.supabase_client import supabase
from app.core.config import WEB_TOKEN_TABLE, WEB_TOKEN_PEPPER


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _token_hash(raw_token: str) -> str:
    pepper = (os.getenv("WEB_TOKEN_PEPPER", WEB_TOKEN_PEPPER) or WEB_TOKEN_PEPPER).strip()
    return _sha256_hex(f"{pepper}:{raw_token}")


def _get_bearer_token() -> Optional[str]:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _auth_debug_enabled() -> bool:
    # Set AUTH_DEBUG=1 on Koyeb to enable debug prints (safe, no raw tokens)
    return _truthy(os.getenv("AUTH_DEBUG"))


def _dbg(msg: str) -> None:
    if _auth_debug_enabled():
        print(msg, flush=True)


def _validate_web_token() -> Dict[str, Any]:
    """
    Shared validator for web session tokens stored in WEB_TOKEN_TABLE.
    Returns:
      {"ok": True, "account_id": "...", "token_hash": "..."} on success
      {"ok": False, "status": 401, "error": "..."} on failure
    """
    raw = _get_bearer_token()
    if not raw:
        _dbg("[auth] missing_token: no Authorization: Bearer <token> header")
        return {"ok": False, "status": 401, "error": "missing_token"}

    th = _token_hash(raw)
    th_prefix = th[:12]  # safe prefix for correlation

    try:
        _dbg(f"[auth] start token_hash_prefix={th_prefix} path={request.path} method={request.method}")

        res = (
            _sb()
            .table(WEB_TOKEN_TABLE)
            .select("account_id, expires_at, revoked")
            .eq("token_hash", th)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            _dbg(f"[auth] invalid_token: token_hash_prefix={th_prefix} not found in {WEB_TOKEN_TABLE}")
            return {"ok": False, "status": 401, "error": "invalid_token"}

        row = rows[0]
        if row.get("revoked") is True:
            _dbg(f"[auth] token_revoked: token_hash_prefix={th_prefix}")
            return {"ok": False, "status": 401, "error": "token_revoked"}

        expires_at = row.get("expires_at")
        if expires_at:
            v = str(expires_at).replace("Z", "+00:00")
            exp_dt = datetime.fromisoformat(v).astimezone(timezone.utc)
            if _now_utc() > exp_dt:
                _dbg(f"[auth] token_expired: token_hash_prefix={th_prefix} exp={exp_dt.isoformat()}")
                return {"ok": False, "status": 401, "error": "token_expired"}

        # touch last_seen_at best-effort (won't break auth if column missing)
        try:
            _sb().table(WEB_TOKEN_TABLE).update(
                {"last_seen_at": _now_utc().isoformat()}
            ).eq("token_hash", th).execute()
        except Exception as e:
            _dbg(f"[auth] last_seen_at update skipped: {type(e).__name__}: {str(e)[:140]}")

        account_id = row.get("account_id")
        if not account_id:
            _dbg(f"[auth] auth_failed: missing account_id in token row token_hash_prefix={th_prefix}")
            return {"ok": False, "status": 401, "error": "auth_failed"}

        _dbg(f"[auth] ok account_id={account_id} token_hash_prefix={th_prefix}")
        return {"ok": True, "account_id": account_id, "token_hash": th}

    except Exception as e:
        _dbg(f"[auth] auth_failed: {type(e).__name__}: {str(e)[:200]}")
        _dbg("[auth] traceback:\n" + traceback.format_exc())
        return {"ok": False, "status": 401, "error": "auth_failed"}


def require_auth_plus(fn: Callable[..., Any]) -> Callable[..., Any]:
    """
    Decorator used by routes that read auth state from flask.g
    Sets:
      g.account_id = <uuid string from web_tokens.account_id>
      g.web_token_hash = <hashed token>
    Does NOT pass ctx into the handler.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verdict = _validate_web_token()
        if not verdict.get("ok"):
            return jsonify({"ok": False, "error": verdict.get("error")}), int(verdict.get("status") or 401)

        g.account_id = verdict["account_id"]
        g.web_token_hash = verdict["token_hash"]
        return fn(*args, **kwargs)

    return wrapper


def require_web_auth(fn: Callable[..., Any]) -> Callable[..., Any]:
    """
    Backward-compatible decorator expected by web_chat routes.

    It validates the same web token, sets flask.g, AND passes a ctx dict
    as the first positional argument to the view function:

      def handler(ctx, ...):
          account_id = ctx["account_id"]
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verdict = _validate_web_token()
        if not verdict.get("ok"):
            return jsonify({"ok": False, "error": verdict.get("error")}), int(verdict.get("status") or 401)

        g.account_id = verdict["account_id"]
        g.web_token_hash = verdict["token_hash"]

        ctx = {
            "account_id": verdict["account_id"],
            "web_token_hash": verdict["token_hash"],
        }
        return fn(ctx, *args, **kwargs)

    return wrapper
