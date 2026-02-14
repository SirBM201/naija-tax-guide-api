# app/services/web_otp_service.py
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

from ..core.config import ENV, OTP_TTL_SECONDS, OTP_RESEND_COOLDOWN_SECONDS
from ..core.supabase_client import supabase

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _hash_code(code: str) -> str:
    # stable hash for OTP compare
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def _make_code() -> str:
    # 6-digit numeric
    return f"{secrets.randbelow(1_000_000):06d}"

def normalize_contact(contact: str) -> str:
    c = (contact or "").strip()
    # basic normalize: remove spaces
    c = c.replace(" ", "")
    return c

def can_resend(contact: str) -> bool:
    # cooldown check (only for unused otps)
    resp = (
        supabase.table("web_otps")
        .select("created_at")
        .eq("contact", contact)
        .is_("used_at", None)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        return True

    try:
        created_at = rows[0]["created_at"].replace("Z", "+00:00")
        created_dt = datetime.fromisoformat(created_at)
    except Exception:
        return True

    return (_now_utc() - created_dt).total_seconds() >= OTP_RESEND_COOLDOWN_SECONDS

def create_otp(contact: str) -> Tuple[str, datetime]:
    code = _make_code()
    expires_at = _now_utc() + timedelta(seconds=OTP_TTL_SECONDS)

    row = {
        "contact": contact,
        "purpose": "login",
        "code_hash": _hash_code(code),
        "expires_at": expires_at.isoformat(),
        "used_at": None,
    }

    # DEV ONLY: store plaintext for convenience (also returned by /start)
    if ENV.lower() != "prod":
        row["code_plain"] = code
    else:
        row["code_plain"] = None

    supabase.table("web_otps").insert(row).execute()
    return code, expires_at

def verify_otp(contact: str, code: str) -> bool:
    code = (code or "").strip()
    if not code:
        return False

    # grab latest unused OTP for contact
    resp = (
        supabase.table("web_otps")
        .select("id, code_hash, expires_at, used_at")
        .eq("contact", contact)
        .is_("used_at", None)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        return False

    otp = rows[0]
    otp_id = otp["id"]

    # expiry check
    try:
        exp = otp["expires_at"].replace("Z", "+00:00")
        exp_dt = datetime.fromisoformat(exp)
        if _now_utc() > exp_dt:
            return False
    except Exception:
        return False

    if _hash_code(code) != (otp.get("code_hash") or ""):
        return False

    # mark used
    supabase.table("web_otps").update({"used_at": _now_utc().isoformat()}).eq("id", otp_id).execute()
    return True

def dev_last_otp(contact: str) -> Optional[str]:
    if ENV.lower() == "prod":
        return None

    resp = (
        supabase.table("web_otps")
        .select("code_plain, created_at")
        .eq("contact", contact)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        return None
    return rows[0].get("code_plain")
