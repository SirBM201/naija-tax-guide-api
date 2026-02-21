# app/core/auth.py
from __future__ import annotations

import os
from functools import wraps
from typing import Any, Callable, Optional, Dict, Tuple

from flask import g, jsonify, request

from app.services.web_tokens_service import (
    extract_any_token,
    validate_token,
)

# ---------------------------------------------------------
# Debug helpers
# ---------------------------------------------------------
def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _auth_debug_enabled() -> bool:
    return _truthy(os.getenv("AUTH_DEBUG"))


def _dbg(msg: str) -> None:
    if _auth_debug_enabled():
        print(msg, flush=True)


def auth_debug_snapshot() -> Dict[str, Any]:
    # Safe snapshot only (no secrets)
    return {
        "auth_debug": _auth_debug_enabled(),
        "cookie_name": (os.getenv("WEB_COOKIE_NAME", "ntg_session") or "ntg_session").strip(),
        "token_table": (os.getenv("WEB_TOKEN_TABLE", "web_sessions") or "web_sessions").strip(),
    }


# ---------------------------------------------------------
# Hashing (single source of truth)
# ---------------------------------------------------------
import hashlib

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def get_web_token_pepper() -> str:
    # Must be set in env
    return (os.getenv("WEB_TOKEN_PEPPER", "") or "").strip()


def token_hash(raw_token: str) -> str:
    pepper = get_web_token_pepper()
    return _sha256_hex(f"{pepper}:{raw_token}")


# ---------------------------------------------------------
# Decorator
# ---------------------------------------------------------
def require_auth_plus(fn: Callable[..., Any]) -> Callable[..., Any]:
    """
    Accepts:
      - Authorization: Bearer <token>
      - Cookie: <WEB_COOKIE_NAME>=<token>

    Sets:
      g.account_id
      g.auth_source = bearer|cookie
    """
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        raw, source = extract_any_token(request)
        if not raw:
            _dbg("[auth] missing_token (no bearer, no cookie)")
            out = {"ok": False, "error": "missing_token"}
            if _auth_debug_enabled():
                out["debug"] = auth_debug_snapshot()
            return jsonify(out), 401

        ok, meta, err = validate_token(raw)
        if not ok:
            _dbg(f"[auth] invalid_token source={source} err={err}")
            out = {"ok": False, "error": "invalid_token"}
            if _auth_debug_enabled():
                out["debug"] = {**auth_debug_snapshot(), "source": source, "err": err}
            return jsonify(out), 401

        g.account_id = meta.get("account_id")
        g.auth_source = source
        _dbg(f"[auth] ok source={source} account_id={g.account_id}")
        return fn(*args, **kwargs)

    return wrapper
