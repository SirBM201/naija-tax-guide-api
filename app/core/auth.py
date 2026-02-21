# app/core/auth.py
from __future__ import annotations

import os
import traceback
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict

from flask import g, jsonify, request

from app.core.config import WEB_TOKEN_TABLE, WEB_TOKEN_PEPPER
from app.core.token_utils import token_hash
from app.services.web_tokens_service import extract_any_token, validate_token


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _auth_debug_enabled() -> bool:
    return _truthy(os.getenv("AUTH_DEBUG"))


def _dbg(msg: str) -> None:
    if _auth_debug_enabled():
        print(msg, flush=True)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def auth_debug_snapshot() -> Dict[str, Any]:
    pepper = (os.getenv("WEB_TOKEN_PEPPER", WEB_TOKEN_PEPPER) or WEB_TOKEN_PEPPER).strip()
    return {
        "web_token_table": (os.getenv("WEB_TOKEN_TABLE", WEB_TOKEN_TABLE) or WEB_TOKEN_TABLE),
        "pepper_len": len(pepper),
        "pepper_prefix_sha256": __import__("hashlib").sha256(pepper.encode("utf-8")).hexdigest()[:12],
        "cookie_name": (os.getenv("WEB_AUTH_COOKIE_NAME", "ntg_session") or "ntg_session").strip(),
        "auth_debug": _auth_debug_enabled(),
        "now_utc": _now_utc().isoformat(),
    }


def require_auth_plus(fn: Callable[..., Any]) -> Callable[..., Any]:
    """
    Cookie-first auth, Bearer fallback.

    Sets:
      g.account_id
      g.token_row
      g.auth_token (raw token)
      g.raw_token_source = "cookie" | "bearer"
      g.web_token_hash (hash)
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            raw, source = extract_any_token(request)

            if not raw:
                _dbg("[auth] missing_token: neither cookie nor bearer present")
                return jsonify({"ok": False, "error": "missing_token"}), 401

            table = (os.getenv("WEB_TOKEN_TABLE", WEB_TOKEN_TABLE) or WEB_TOKEN_TABLE).strip() or WEB_TOKEN_TABLE

            ok, payload, err = validate_token(raw, table=table, touch=True)
            if not ok:
                _dbg(f"[auth] deny src={source} err={err} path={request.path} method={request.method}")
                return jsonify({"ok": False, "error": err or "Unauthorized"}), 401

            account_id = (payload.get("account_id") or "").strip()
            token_row = payload.get("token_row") or {}

            g.account_id = account_id
            g.token_row = token_row
            g.auth_token = raw
            g.raw_token_source = source
            g.web_token_hash = token_hash(raw, fallback_pepper=WEB_TOKEN_PEPPER)

            _dbg(f"[auth] ok account_id={account_id} src={source} path={request.path}")
            return fn(*args, **kwargs)

        except Exception as e:
            _dbg(f"[auth] auth_failed: {type(e).__name__}: {str(e)[:220]}")
            if _auth_debug_enabled():
                _dbg("[auth] traceback:\n" + traceback.format_exc())
            return jsonify({"ok": False, "error": "auth_failed"}), 401

    return wrapper
