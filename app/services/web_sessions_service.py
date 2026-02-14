# app/services/web_sessions_service.py
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase
from ..core.config import WEB_SESSION_TTL_DAYS


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def create_web_session(
    account_id: str,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates a new web session and returns:
      { ok, token, session_id, expires_at }
    Stores only token_hash in DB.
    """
    token_plain = secrets.token_urlsafe(32)
    token_hash = _sha256_hex(token_plain)

    expires_at = _now_utc() + timedelta(days=WEB_SESSION_TTL_DAYS)

    ins = (
        supabase.table("web_sessions")
        .insert(
            {
                "account_id": account_id,
                "token_hash": token_hash,
                "expires_at": expires_at.isoformat(),
                "ip": ip,
                "user_agent": user_agent,
            }
        )
        .execute()
    )

    # Supabase python returns .data list
    session_row = (ins.data or [{}])[0]
    return {
        "ok": True,
        "token": token_plain,
        "session_id": session_row.get("id"),
        "expires_at": expires_at.isoformat(),
    }


def get_session_by_token(token_plain: str) -> Optional[Dict[str, Any]]:
    token_hash = _sha256_hex(token_plain)

    res = (
        supabase.table("web_sessions")
        .select("*")
        .eq("token_hash", token_hash)
        .limit(1)
        .execute()
    )
    row = (res.data or [None])[0]
    return row


def validate_web_session(token_plain: str) -> Tuple[bool, Optional[str], str]:
    """
    Returns (ok, account_id, reason)
    """
    row = get_session_by_token(token_plain)
    if not row:
        return False, None, "invalid_session"

    if row.get("revoked_at"):
        return False, None, "revoked"

    expires_at = row.get("expires_at")
    if not expires_at:
        return False, None, "expired"

    try:
        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except Exception:
        return False, None, "expired"

    if exp <= _now_utc():
        return False, None, "expired"

    return True, row.get("account_id"), "ok"


def touch_session_best_effort(token_plain: str) -> None:
    try:
        row = get_session_by_token(token_plain)
        if not row:
            return
        supabase.table("web_sessions").update(
            {"last_seen_at": _now_utc().isoformat()}
        ).eq("id", row["id"]).execute()
    except Exception:
        return


def revoke_session(token_plain: str) -> bool:
    row = get_session_by_token(token_plain)
    if not row:
        return False
    supabase.table("web_sessions").update(
        {"revoked_at": _now_utc().isoformat()}
    ).eq("id", row["id"]).execute()
    return True
