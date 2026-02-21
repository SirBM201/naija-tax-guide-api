# app/services/web_tokens_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Request

from app.core.supabase_client import supabase
from app.core.auth import token_hash  # single source of truth for hashing


# -----------------------------
# Defaults / env
# -----------------------------
DEFAULT_TABLE = "web_sessions"


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _table_name(default: str = DEFAULT_TABLE) -> str:
    """
    Prefer explicit table name from env if present.
    """
    return (_env("WEB_TOKEN_TABLE") or default).strip() or default


def _cookie_name() -> str:
    """
    Align with web_auth.py cookie config.
    We keep fallbacks so older envs don't break.
    """
    return (
        _env("WEB_AUTH_COOKIE_NAME")
        or _env("WEB_COOKIE_NAME")
        or _env("WEB_COOKIE_NAME_LEGACY")
        or "ntg_session"
    ).strip()


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Any) -> Optional[datetime]:
    """
    Robust ISO parser for values like:
      - "2026-02-21T10:00:00Z"
      - "2026-02-21T10:00:00+00:00"
      - naive timestamps (treated as UTC)
    """
    if not value:
        return None
    try:
        v = str(value).strip()
        if not v:
            return None
        v = v.replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


# -----------------------------
# Token extraction
# -----------------------------
def extract_bearer_token(req: Request) -> Optional[str]:
    """
    Accept:
      - Authorization: Bearer <token>
      - X-Auth-Token: <token>
    """
    auth = (req.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        t = auth[7:].strip()
        return t or None

    t2 = (req.headers.get("X-Auth-Token") or "").strip()
    return t2 or None


def extract_cookie_token(req: Request, cookie_name: Optional[str] = None) -> Optional[str]:
    """
    Extract token from HttpOnly cookie.
    """
    name = (cookie_name or _cookie_name()).strip() or _cookie_name()
    try:
        t = (req.cookies.get(name) or "").strip()
        return t or None
    except Exception:
        return None


def extract_any_token(req: Request) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (token, source) where source is one of:
      - "cookie"
      - "bearer"
      - None
    Cookie-first is recommended for browser flows, but we keep bearer support
    for scripts / debugging.
    """
    t = extract_cookie_token(req)
    if t:
        return t, "cookie"

    t = extract_bearer_token(req)
    if t:
        return t, "bearer"

    return None, None


# -----------------------------
# DB access
# -----------------------------
def _get_session_row_by_token(table: str, raw_token: str) -> Optional[Dict[str, Any]]:
    raw_token = (raw_token or "").strip()
    if not raw_token:
        return None

    table = _table_name(table)
    th = token_hash(raw_token)

    try:
        res = (
            _sb()
            .table(table)
            .select("*")
            .eq("token_hash", th)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        return rows[0] if rows else None
    except Exception:
        return None


def touch_last_seen(raw_token: str, table: str = DEFAULT_TABLE) -> None:
    """
    Best-effort update last_seen_at so you can track activity.
    Never raises.
    """
    raw_token = (raw_token or "").strip()
    if not raw_token:
        return

    table = _table_name(table)
    if not _has_column(table, "last_seen_at"):
        return

    try:
        th = token_hash(raw_token)
        _sb().table(table).update({"last_seen_at": _iso(_now_utc())}).eq("token_hash", th).execute()
    except Exception:
        return


# -----------------------------
# Public API
# -----------------------------
def validate_token(
    raw_token: str,
    table: str = DEFAULT_TABLE,
    touch: bool = True,
) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    """
    Returns:
      (ok, {"account_id": <uuid>, "token_row": <row>}, error)

    Validates:
      - token exists
      - not revoked (revoked=true OR revoked_at set)
      - not expired
      - account_id present
    """
    raw_token = (raw_token or "").strip()
    table = _table_name(table)

    if not raw_token:
        return False, {}, "missing_token"

    row = _get_session_row_by_token(table, raw_token)
    if not row:
        return False, {}, "invalid_token"

    # Support BOTH schemas:
    # - revoked (bool)
    # - revoked_at (timestamp)
    if row.get("revoked") is True:
        return False, {}, "token_revoked"
    if row.get("revoked_at"):
        return False, {}, "token_revoked"

    exp = _parse_iso(row.get("expires_at"))
    if not exp or exp <= _now_utc():
        return False, {}, "token_expired"

    account_id = str(row.get("account_id") or "").strip()
    if not account_id:
        return False, {}, "invalid_token"

    if touch:
        touch_last_seen(raw_token, table=table)

    return True, {"account_id": account_id, "token_row": row}, None


def revoke_token(
    raw_token: str,
    table: str = DEFAULT_TABLE,
) -> Tuple[bool, Optional[str]]:
    """
    Best-effort revoke. Idempotent.
    Supports:
      - revoked (bool)
      - revoked_at (timestamp)

    If token doesn't exist -> treat as already logged out.
    """
    raw_token = (raw_token or "").strip()
    table = _table_name(table)

    if not raw_token:
        return False, "missing_token"

    row = _get_session_row_by_token(table, raw_token)
    if not row:
        return True, None

    th = token_hash(raw_token)

    updates: Dict[str, Any] = {}
    if _has_column(table, "revoked"):
        updates["revoked"] = True
    if _has_column(table, "revoked_at"):
        updates["revoked_at"] = _iso(_now_utc())

    if not updates:
        return False, "revoke_not_supported"

    try:
        _sb().table(table).update(updates).eq("token_hash", th).execute()
        return True, None
    except Exception:
        return False, "logout_failed"
