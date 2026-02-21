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


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _auth_debug_enabled() -> bool:
    return _truthy(os.getenv("AUTH_DEBUG"))


def _dbg(msg: str) -> None:
    if _auth_debug_enabled():
        print(msg, flush=True)


def get_web_token_pepper() -> str:
    return (os.getenv("WEB_TOKEN_PEPPER", WEB_TOKEN_PEPPER) or WEB_TOKEN_PEPPER).strip()


def token_hash(raw_token: str) -> str:
    pepper = get_web_token_pepper()
    return _sha256_hex(f"{pepper}:{raw_token}")


def _cookie_name() -> str:
    return (os.getenv("WEB_AUTH_COOKIE_NAME", "ntg_session") or "ntg_session").strip()


def _get_bearer_token() -> Optional[str]:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth:
        return None
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _get_cookie_token() -> Optional[str]:
    name = _cookie_name()
    v = request.cookies.get(name)
    v = (v or "").strip()
    return v or None


def auth_debug_snapshot() -> Dict[str, Any]:
    pepper = get_web_token_pepper()
    return {
        "web_token_table": (os.getenv("WEB_TOKEN_TABLE", WEB_TOKEN_TABLE) or WEB_TOKEN_TABLE),
        "pepper_len": len(pepper),
        "pepper_prefix_sha256": _sha256_hex(pepper)[:12],
        "cookie_name": _cookie_name(),
        "auth_debug": _auth_debug_enabled(),
    }


def require_auth_plus(fn: Callable[..., Any]) -> Callable[..., Any]:
    """
    Cookie-first auth, Bearer fallback.
    Sets:
      g.account_id
      g.web_token_hash
      g.raw_token_source = "cookie" | "bearer"
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        raw = _get_cookie_token()
        source = "cookie"
        if not raw:
            raw = _get_bearer_token()
            source = "bearer"

        if not raw:
            _dbg("[auth] missing_token: neither cookie nor bearer present")
            return jsonify({"ok": False, "error": "missing_token"}), 401

        th = token_hash(raw)
        th_prefix = th[:12]
        table = (os.getenv("WEB_TOKEN_TABLE", WEB_TOKEN_TABLE) or WEB_TOKEN_TABLE).strip()

        try:
            _dbg(f"[auth] start src={source} token_hash_prefix={th_prefix} path={request.path} method={request.method}")

            res = (
                _sb()
                .table(table)
                .select("account_id, expires_at, revoked, revoked_at")
                .eq("token_hash", th)
                .limit(1)
                .execute()
            )
            rows = (res.data or []) if hasattr(res, "data") else []
            if not rows:
                _dbg(f"[auth] invalid_token: token_hash_prefix={th_prefix} not found in {table}")
                return jsonify({"ok": False, "error": "invalid_token"}), 401

            row = rows[0]

            # support both revoke styles
            if row.get("revoked") is True or row.get("revoked_at"):
                _dbg(f"[auth] token_revoked: token_hash_prefix={th_prefix}")
                return jsonify({"ok": False, "error": "token_revoked"}), 401

            expires_at = row.get("expires_at")
            if expires_at:
                v = str(expires_at).replace("Z", "+00:00")
                exp_dt = datetime.fromisoformat(v).astimezone(timezone.utc)
                if _now_utc() > exp_dt:
                    _dbg(f"[auth] token_expired: token_hash_prefix={th_prefix} exp={exp_dt.isoformat()}")
                    return jsonify({"ok": False, "error": "token_expired"}), 401

            # touch last_seen_at best-effort
            try:
                _sb().table(table).update({"last_seen_at": _now_utc().isoformat()}).eq("token_hash", th).execute()
            except Exception as e:
                _dbg(f"[auth] last_seen_at update skipped: {type(e).__name__}: {str(e)[:160]}")

            g.account_id = row.get("account_id")
            g.web_token_hash = th
            g.raw_token_source = source

            _dbg(f"[auth] ok account_id={g.account_id} src={source} token_hash_prefix={th_prefix}")
            return fn(*args, **kwargs)

        except Exception as e:
            _dbg(f"[auth] auth_failed: {type(e).__name__}: {str(e)[:220]}")
            _dbg("[auth] traceback:\n" + traceback.format_exc())
            return jsonify({"ok": False, "error": "auth_failed"}), 401

    return wrapper
