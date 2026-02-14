# app/services/web_tokens_service.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Request

from app.core.supabase_client import supabase


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
    """
    Table expected: web_tokens
      - token (text, unique)
      - account_id (uuid)
      - expires_at (timestamptz)
      - revoked_at (timestamptz nullable)
      - created_at (timestamptz)
    """
    try:
        res = (
            supabase.table("web_tokens")
            .select("*")
            .eq("token", token)
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

    if row.get("revoked_at"):
        return False, {}, "Session expired"

    exp = _parse_iso(row.get("expires_at"))
    if not exp or exp <= _now_utc():
        return False, {}, "Session expired"

    account_id = (row.get("account_id") or "").strip()
    if not account_id:
        return False, {}, "Unauthorized"

    return True, {"account_id": account_id, "token_row": row}, None


def revoke_token(token: str) -> Tuple[bool, Optional[str]]:
    token = (token or "").strip()
    if not token:
        return False, "Unauthorized"

    # idempotent: ok if token row missing
    row = _get_token_row(token)
    if not row:
        return True, None

    try:
        supabase.table("web_tokens").update({"revoked_at": _iso(_now_utc())}).eq("token", token).execute()
        return True, None
    except Exception:
        return False, "Failed to logout"
