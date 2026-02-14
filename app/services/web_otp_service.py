# app/services/web_otp_service.py
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase
from ..core.config import WEB_OTP_TTL_MINUTES, WEB_OTP_COOLDOWN_SECONDS


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _gen_code() -> str:
    # 6-digit OTP
    return f"{random.randint(0, 999999):06d}"


def otp_request_cooldown_ok(contact: str, purpose: str) -> bool:
    """
    Prevent hammering: ensure last request is older than WEB_OTP_COOLDOWN_SECONDS.
    """
    res = (
        supabase.table("web_otps")
        .select("created_at")
        .eq("contact", contact)
        .eq("purpose", purpose)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    row = (res.data or [None])[0]
    if not row:
        return True

    try:
        last = datetime.fromisoformat(row["created_at"].replace("Z", "+00:00"))
    except Exception:
        return True

    return (_now_utc() - last).total_seconds() >= WEB_OTP_COOLDOWN_SECONDS


def create_otp(contact: str, purpose: str = "web_login") -> Dict[str, Any]:
    code_plain = _gen_code()
    code_hash = _sha256_hex(code_plain)
    expires_at = _now_utc() + timedelta(minutes=WEB_OTP_TTL_MINUTES)

    ins = (
        supabase.table("web_otps")
        .insert(
            {
                "contact": contact,
                "purpose": purpose,
                "code_plain": code_plain,   # DEV-friendly (you already have it)
                "code_hash": code_hash,
                "expires_at": expires_at.isoformat(),
                "used": False,
                "phone_e164": contact,      # keep in sync with your extra column
                "otp_code": code_plain,     # keep in sync with your extra column
            }
        )
        .execute()
    )

    row = (ins.data or [{}])[0]
    return {
        "ok": True,
        "otp_id": row.get("id"),
        "expires_at": expires_at.isoformat(),
        "code_plain": code_plain,
    }


def verify_otp(contact: str, code_plain: str, purpose: str = "web_login") -> Tuple[bool, str]:
    """
    Returns (ok, reason)
    reason: ok | invalid | expired | used
    """
    code_hash = _sha256_hex(code_plain)

    res = (
        supabase.table("web_otps")
        .select("*")
        .eq("contact", contact)
        .eq("purpose", purpose)
        .eq("code_hash", code_hash)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    row = (res.data or [None])[0]
    if not row:
        return False, "invalid"

    if row.get("used") is True or row.get("used_at"):
        return False, "used"

    expires_at = row.get("expires_at")
    if not expires_at:
        return False, "expired"

    try:
        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except Exception:
        return False, "expired"

    if exp <= _now_utc():
        return False, "expired"

    # mark used
    supabase.table("web_otps").update(
        {"used": True, "used_at": _now_utc().isoformat()}
    ).eq("id", row["id"]).execute()

    return True, "ok"
