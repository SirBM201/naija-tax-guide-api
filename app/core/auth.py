from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import request, jsonify, g
from werkzeug.exceptions import Unauthorized

from app.core.supabase_client import supabase


# -----------------------------------------------------------------------------
# Config (matches your Supabase schema)
# -----------------------------------------------------------------------------
WEB_TOKEN_PEPPER = (os.getenv("WEB_TOKEN_PEPPER") or "").strip()
WEB_SESSIONS_TABLE = (os.getenv("WEB_SESSIONS_TABLE") or "web_sessions").strip()

# Column names (your schema)
COL_TOKEN_HASH = (os.getenv("WEB_SESSIONS_COL_TOKEN_HASH") or "token_hash").strip()
COL_ACCOUNT_ID = (os.getenv("WEB_SESSIONS_COL_ACCOUNT_ID") or "account_id").strip()
COL_EXPIRES_AT = (os.getenv("WEB_SESSIONS_COL_EXPIRES_AT") or "expires_at").strip()
COL_REVOKED_AT = (os.getenv("WEB_SESSIONS_COL_REVOKED_AT") or "revoked_at").strip()


@dataclass
class AuthContext:
    account_id: str
    token: str


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(raw_token: str) -> str:
    """
    Server stores token_hash in DB, not the raw token.
    We compute sha256(pepper + ":" + token).
    """
    if not WEB_TOKEN_PEPPER:
        # Fail closed: if you didn't set WEB_TOKEN_PEPPER, auth must not work.
        raise RuntimeError("WEB_TOKEN_PEPPER is not set in environment.")
    msg = f"{WEB_TOKEN_PEPPER}:{raw_token}".encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


def _get_bearer_token() -> Optional[str]:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth:
        return None
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        return token or None
    return None


def _find_active_session_by_token(raw_token: str) -> Optional[Dict[str, Any]]:
    token_hash = _hash_token(raw_token)

    # Find session by token_hash and not revoked
    q = (
        supabase.table(WEB_SESSIONS_TABLE)
        .select(f"{COL_ACCOUNT_ID},{COL_EXPIRES_AT},{COL_REVOKED_AT}")
        .eq(COL_TOKEN_HASH, token_hash)
        .is_(COL_REVOKED_AT, None)
        .limit(1)
    )
    res = q.execute()
    rows = (res.data or []) if hasattr(res, "data") else []
    if not rows:
        return None

    row = rows[0]
    # Expiry check
    expires_at = row.get(COL_EXPIRES_AT)
    if expires_at:
        try:
            dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if dt <= _now_utc():
                return None
        except Exception:
            # If expiry is malformed, treat as invalid
            return None

    return row


def require_auth() -> AuthContext:
    raw_token = _get_bearer_token()
    if not raw_token:
        raise Unauthorized("Missing bearer token")

    row = _find_active_session_by_token(raw_token)
    if not row:
        raise Unauthorized("Unauthorized")

    account_id = (row.get(COL_ACCOUNT_ID) or "").strip()
    if not account_id:
        raise Unauthorized("Unauthorized")

    return AuthContext(account_id=account_id, token=raw_token)


def require_auth_plus() -> Dict[str, Any]:
    """
    Returns auth + subscription + credit balance (for /api/billing/me etc.).
    """
    ctx = require_auth()

    # Lazy imports avoid circular dependencies
    from app.services.subscriptions_service import get_subscription_status
    from app.services.credits_service import get_credit_balance

    sub = get_subscription_status(ctx.account_id)
    credits = get_credit_balance(ctx.account_id)

    return {
        "account_id": ctx.account_id,
        "subscription": sub,
        "credits": {"balance": credits},
    }


def attach_auth_handlers(app) -> None:
    """
    Optional: standardized 401 JSON.
    """
    @app.errorhandler(Unauthorized)
    def _unauth(err):
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
