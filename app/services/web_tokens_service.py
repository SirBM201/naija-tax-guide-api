# app/services/web_tokens_service.py
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Request
from app.core.supabase_client import supabase


# Your real table/columns (confirmed from your SQL results)
TABLE = "web_sessions"
COL_ACCOUNT_ID = "account_id"
COL_EXPIRES_AT = "expires_at"
COL_REVOKED_AT = "revoked_at"
COL_TOKEN_HASH = "token_hash"

# IMPORTANT:
# Use the SAME secret + hashing strategy as your existing verify-otp code.
# If your verify-otp uses a pepper/secret, set it here too.
WEB_TOKEN_PEPPER = (os.getenv("WEB_TOKEN_PEPPER", "") or "").strip()


# -----------------------------
# Time helpers
# -----------------------------
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


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# -----------------------------
# Token extraction
# -----------------------------
def extract_bearer_token(req: Request) -> Optional[str]:
    auth = (req.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        t = auth[7:].strip()
        return t or None

    t2 = (req.headers.get("X-Auth-Token") or "").strip()
    return t2 or None


# -----------------------------
# Hashing (must match verify-otp)
# -----------------------------
def _token_hash(token: str) -> str:
    """
    Hash strategy:
    - If WEB_TOKEN_PEPPER is set, use HMAC-SHA256(pepper, token)
    - Otherwise use SHA256(token)

    NOTE:
    This must match your /verify-otp implementation.
    """
    token = (token or "").strip()
    if not token:
        return ""

    if WEB_TOKEN_PEPPER:
        return hmac.new(WEB_TOKEN_PEPPER.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# -----------------------------
# DB access
# -----------------------------
def _get_session_row_by_token(token: str) -> Optional[Dict[str, Any]]:
    th = _token_hash(token)
    if not th:
        return None

    try:
        res = (
            supabase.table(TABLE)
            .select("*")
            .eq(COL_TOKEN_HASH, th)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        return rows[0] if rows else None
    except Exception:
        return None


# -----------------------------
# Public API
# -----------------------------
def validate_token(token: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    token = (token or "").strip()
    if not token:
        return False, {}, "Unauthorized"

    row = _get_session_row_by_token(token)
    if not row:
        return False, {}, "Unauthorized"

    if row.get(COL_REVOKED_AT):
        return False, {}, "Session expired"

    exp = _parse_iso(row.get(COL_EXPIRES_AT))
    if not exp or exp <= _now_utc():
        return False, {}, "Session expired"

    account_id = (row.get(COL_ACCOUNT_ID) or "").strip()
    if not account_id:
        return False, {}, "Unauthorized"

    return True, {"account_id": account_id, "token_row": row}, None


def revoke_token(token: str) -> Tuple[bool, Optional[str]]:
    token = (token or "").strip()
    if not token:
        return False, "Unauthorized"

    row = _get_session_row_by_token(token)
    if not row:
        return True, None  # idempotent

    th = _token_hash(token)
    try:
        (
            supabase.table(TABLE)
            .update({COL_REVOKED_AT: _iso(_now_utc())})
            .eq(COL_TOKEN_HASH, th)
            .execute()
        )
        return True, None
    except Exception:
        return False, "Failed to logout"
