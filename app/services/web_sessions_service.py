# app/services/web_sessions_service.py
from __future__ import annotations

import os
import secrets
import hashlib
from typing import Any, Dict, Optional, Tuple
from datetime import datetime, timezone, timedelta

from app.core.supabase_client import supabase


def _env_int(name: str, default: int) -> int:
    try:
        return int((os.getenv(name, str(default)) or str(default)).strip())
    except Exception:
        return default


WEB_SESSION_TTL_DAYS = _env_int("WEB_SESSION_TTL_DAYS", 30)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _gen_token() -> str:
    return secrets.token_urlsafe(32)


def create_web_session(*, account_id: str, ip: str | None = None, user_agent: str | None = None) -> Dict[str, Any]:
    token = _gen_token()
    token_hash = _hash_token(token)

    now = _now_utc()
    expires = now + timedelta(days=WEB_SESSION_TTL_DAYS)

    payload = {
        "account_id": account_id,
        "token_hash": token_hash,
        "token_plain": token,  # keep for dev/debug (your table may include it)
        "expires_at": _iso(expires),
        "revoked_at": None,
        "last_seen_at": _iso(now),
        "ip": ip,
        "user_agent": user_agent,
        "created_at": _iso(now),
    }

    # Insert best-effort; if some columns don't exist, retry with minimal set
    try:
        supabase().table("web_sessions").insert(payload).execute()
    except Exception:
        minimal = {
            "account_id": account_id,
            "token_hash": token_hash,
            "expires_at": _iso(expires),
            "created_at": _iso(now),
        }
        try:
            supabase().table("web_sessions").insert(minimal).execute()
        except Exception as e:
            return {"ok": False, "error": f"db_error:{str(e)}"}

    return {"ok": True, "token": token, "expires_at": _iso(expires)}


def validate_web_session(token: str) -> Tuple[bool, Optional[str], str]:
    """
    Returns (ok, account_id, reason)
    """
    token = (token or "").strip()
    if not token:
        return False, None, "missing_token"

    token_hash = _hash_token(token)

    try:
        res = (
            supabase()
            .table("web_sessions")
            .select("account_id,expires_at,revoked_at")
            .eq("token_hash", token_hash)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return False, None, f"db_error:{str(e)}"

    row = (res.data or [None])[0]
    if not row:
        return False, None, "invalid_token"

    if row.get("revoked_at"):
        return False, None, "revoked"

    expires_at = _parse_dt(row.get("expires_at"))
    if not expires_at or expires_at <= _now_utc():
        return False, None, "expired"

    return True, row.get("account_id"), "ok"


def touch_session_best_effort(token: str) -> None:
    token = (token or "").strip()
    if not token:
        return
    token_hash = _hash_token(token)
    try:
        supabase().table("web_sessions").update({"last_seen_at": _iso(_now_utc())}).eq("token_hash", token_hash).execute()
    except Exception:
        return


def revoke_session(token: str) -> bool:
    token = (token or "").strip()
    if not token:
        return False
    token_hash = _hash_token(token)
    try:
        supabase().table("web_sessions").update({"revoked_at": _iso(_now_utc())}).eq("token_hash", token_hash).execute()
        return True
    except Exception:
        return False
