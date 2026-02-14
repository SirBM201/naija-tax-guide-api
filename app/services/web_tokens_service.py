# app/services/web_tokens_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Request
from app.core.supabase_client import supabase


WEB_TOKEN_TABLE = (os.getenv("WEB_TOKEN_TABLE", "web_tokens") or "web_tokens").strip()

# Column names (in case your table uses different names)
COL_TOKEN = (os.getenv("WEB_TOKEN_COL_TOKEN", "token") or "token").strip()
COL_ACCOUNT_ID = (os.getenv("WEB_TOKEN_COL_ACCOUNT_ID", "account_id") or "account_id").strip()
COL_EXPIRES_AT = (os.getenv("WEB_TOKEN_COL_EXPIRES_AT", "expires_at") or "expires_at").strip()
COL_REVOKED_AT = (os.getenv("WEB_TOKEN_COL_REVOKED_AT", "revoked_at") or "revoked_at").strip()


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


def extract_bearer_token(req: Request) -> Optional[str]:
    auth = (req.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        t = auth[7:].strip()
        return t or None
    t2 = (req.headers.get("X-Auth-Token") or "").strip()
    return t2 or None


def _get_token_row(token: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            supabase.table(WEB_TOKEN_TABLE)
            .select("*")
            .eq(COL_TOKEN, token)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        return rows[0] if rows else None
    except Exception:
        return None


def validate_token(token: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    token = (token or "").strip()
    if not token:
        return False, {}, "Unauthorized"

    row = _get_token_row(token)
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

    row = _get_token_row(token)
    if not row:
        return True, None  # idempotent

    try:
        (
            supabase.table(WEB_TOKEN_TABLE)
            .update({COL_REVOKED_AT: _iso(_now_utc())})
            .eq(COL_TOKEN, token)
            .execute()
        )
        return True, None
    except Exception:
        return False, "Failed to logout"
