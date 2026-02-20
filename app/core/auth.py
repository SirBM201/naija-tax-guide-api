# app/core/auth.py
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Optional

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


def require_auth_plus(fn: Callable[..., Any]) -> Callable[..., Any]:
    """
    Validates web session tokens stored in WEB_TOKEN_TABLE.
    Sets:
      g.account_id = <uuid string from web_tokens.account_id>
      g.web_token_hash = <hashed token>
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        raw = _get_bearer_token()
        if not raw:
            return jsonify({"ok": False, "error": "missing_token"}), 401

        th = _token_hash(raw)

        try:
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
                return jsonify({"ok": False, "error": "invalid_token"}), 401

            row = rows[0]
            if row.get("revoked") is True:
                return jsonify({"ok": False, "error": "token_revoked"}), 401

            expires_at = row.get("expires_at")
            if expires_at:
                # Supabase may return ISO string with Z / offset
                v = str(expires_at).replace("Z", "+00:00")
                exp_dt = datetime.fromisoformat(v)
                if _now_utc() > exp_dt.astimezone(timezone.utc):
                    return jsonify({"ok": False, "error": "token_expired"}), 401

            # touch last_seen_at best-effort (won't break auth if column missing)
            try:
                _sb().table(WEB_TOKEN_TABLE).update(
                    {"last_seen_at": _now_utc().isoformat()}
                ).eq("token_hash", th).execute()
            except Exception:
                pass

            g.account_id = row.get("account_id")
            g.web_token_hash = th
            return fn(*args, **kwargs)

        except Exception:
            return jsonify({"ok": False, "error": "auth_failed"}), 401

    return wrapper
