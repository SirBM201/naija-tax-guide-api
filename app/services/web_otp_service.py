# app/services/web_otp_service.py
from __future__ import annotations

import os
import secrets
import hashlib
from typing import Any, Dict, Optional, Tuple
from datetime import datetime, timezone, timedelta

from app.core.supabase_client import supabase


# ----------------------------
# Safe env config (no import crashes)
# ----------------------------
def _env_int(name: str, default: int) -> int:
    try:
        return int((os.getenv(name, str(default)) or str(default)).strip())
    except Exception:
        return default


WEB_OTP_TTL_MINUTES = _env_int("WEB_OTP_TTL_MINUTES", 10)
WEB_OTP_COOLDOWN_SECONDS = _env_int("WEB_OTP_COOLDOWN_SECONDS", 45)


# ----------------------------
# Time helpers
# ----------------------------
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


# ----------------------------
# Hash helpers
# ----------------------------
def _hash_code(code_plain: str) -> str:
    # Simple SHA256 is fine for OTP hashes (short-lived).
    return hashlib.sha256(code_plain.encode("utf-8")).hexdigest()


def _gen_code(length: int = 6) -> str:
    # 6-digit numeric code
    # Use secrets for cryptographic randomness
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))


# ----------------------------
# Cooldown
# ----------------------------
def otp_request_cooldown_ok(contact: str, purpose: str) -> bool:
    """
    Returns True if user is allowed to request a new OTP now.
    """
    contact = (contact or "").strip()
    purpose = (purpose or "").strip() or "web_login"
    if not contact:
        return False

    try:
        res = (
            supabase()
            .table("web_otps")
            .select("created_at")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
    except Exception:
        # If DB check fails, be safe and allow (so you don't lock everyone out)
        return True

    row = (res.data or [None])[0]
    if not row:
        return True

    created = _parse_dt(row.get("created_at"))
    if not created:
        return True

    return (_now_utc() - created).total_seconds() >= WEB_OTP_COOLDOWN_SECONDS


# ----------------------------
# Create OTP
# ----------------------------
def create_otp(*, contact: str, purpose: str = "web_login") -> Dict[str, Any]:
    """
    Creates OTP row and returns {code_plain, expires_at, id}
    Note: code_plain is returned so the caller can optionally show it in dev.
    """
    contact = (contact or "").strip()
    purpose = (purpose or "").strip() or "web_login"

    code_plain = _gen_code(6)
    code_hash = _hash_code(code_plain)

    now = _now_utc()
    expires = now + timedelta(minutes=WEB_OTP_TTL_MINUTES)

    payload = {
        "contact": contact,
        "purpose": purpose,
        "code_hash": code_hash,
        # keep both fields because your table has both; code_plain may be used in dev
        "code_plain": code_plain,
        "phone_e164": contact,
        "otp_code": code_plain,
        "expires_at": _iso(expires),
        "used": False,
        "used_at": None,
        "created_at": _iso(now),
    }

    # Insert best-effort
    try:
        res = supabase().table("web_otps").insert(payload, returning="representation").execute()
        row = (res.data or [None])[0] or {}
        otp_id = row.get("id")
    except Exception:
        otp_id = None

    return {
        "ok": True,
        "id": otp_id,
        "contact": contact,
        "purpose": purpose,
        "code_plain": code_plain,
        "expires_at": _iso(expires),
    }


# ----------------------------
# Verify OTP
# ----------------------------
def verify_otp(*, contact: str, code_plain: str, purpose: str = "web_login") -> Tuple[bool, str]:
    """
    Returns (ok, reason)
    """
    contact = (contact or "").strip()
    code_plain = (code_plain or "").strip()
    purpose = (purpose or "").strip() or "web_login"

    if not contact or not code_plain:
        return False, "missing_params"

    try:
        res = (
            supabase()
            .table("web_otps")
            .select("id,code_hash,expires_at,used,used_at,created_at")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return False, f"db_error:{str(e)}"

    row = (res.data or [None])[0]
    if not row:
        return False, "otp_not_found"

    if bool(row.get("used")):
        return False, "otp_used"

    expires_at = _parse_dt(row.get("expires_at"))
    if not expires_at or expires_at <= _now_utc():
        return False, "otp_expired"

    expected_hash = (row.get("code_hash") or "").strip()
    if not expected_hash:
        return False, "otp_invalid"

    if _hash_code(code_plain) != expected_hash:
        return False, "otp_invalid"

    # Mark used (best-effort)
    try:
        supabase().table("web_otps").update(
            {"used": True, "used_at": _iso(_now_utc())}
        ).eq("id", row["id"]).execute()
    except Exception:
        pass

    return True, "ok"
