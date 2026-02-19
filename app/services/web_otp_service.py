# app/services/web_otp_service.py
from __future__ import annotations

import os
import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from ..core.supabase_client import supabase


# ------------------------------------------------------------
# Config
# ------------------------------------------------------------

OTP_ENABLED = (os.getenv("WEB_OTP_ENABLED", "0").strip() == "1")
OTP_TTL_MINUTES = int((os.getenv("WEB_OTP_TTL_MINUTES", "10") or "10").strip())
OTP_LEN = int((os.getenv("WEB_OTP_LEN", "6") or "6").strip())

# Stub OTP for testing when WEB_OTP_ENABLED=0
STUB_OTP = (os.getenv("WEB_OTP_STUB_CODE", "123456") or "123456").strip()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None

def _sb():
    try:
        return supabase()
    except TypeError:
        return supabase

def _table(name: str):
    return _sb().table(name)

def _normalize_phone(phone: str) -> str:
    return (phone or "").strip()

def _gen_otp() -> str:
    low = 10 ** (OTP_LEN - 1)
    high = (10 ** OTP_LEN) - 1
    return str(random.randint(low, high))


# ------------------------------------------------------------
# Public API (these MUST exist to satisfy imports)
# ------------------------------------------------------------

def request_web_login_otp(phone: str) -> Dict[str, Any]:
    """
    Creates an OTP for web login.

    If WEB_OTP_ENABLED=0:
      - operates in stub mode
      - returns ok immediately (and includes otp for testing)
      - best-effort stores into web_otps if table exists
    """
    phone = _normalize_phone(phone)
    if not phone:
        return {"ok": False, "error": "missing_phone"}

    if not OTP_ENABLED:
        _best_effort_store_otp(phone, STUB_OTP)
        return {"ok": True, "mode": "stub", "ttl_minutes": OTP_TTL_MINUTES, "otp": STUB_OTP}

    otp = _gen_otp()
    _best_effort_store_otp(phone, otp)
    # Provider send (SMS/WhatsApp) can be added later without changing contract
    return {"ok": True, "mode": "real", "ttl_minutes": OTP_TTL_MINUTES}


def verify_web_login_otp(phone: str, otp: str) -> Dict[str, Any]:
    """
    Verifies OTP and issues a web token.

    If WEB_OTP_ENABLED=0:
      - accepts STUB_OTP
      - returns a token (best-effort persisted)
    """
    phone = _normalize_phone(phone)
    otp = (otp or "").strip()

    if not phone or not otp:
        return {"ok": False, "error": "missing_phone_or_otp"}

    if not OTP_ENABLED:
        if otp != STUB_OTP:
            return {"ok": False, "error": "invalid_otp"}
        token = _best_effort_issue_web_token(phone)
        return {"ok": True, "mode": "stub", "token": token}

    rec = _best_effort_get_latest_otp(phone)
    if not rec:
        return {"ok": False, "error": "otp_not_found"}

    code = (rec.get("otp") or "").strip()
    expires_at = _parse_iso(rec.get("expires_at"))

    if not code or not expires_at:
        return {"ok": False, "error": "otp_record_invalid"}

    if _now_utc() > expires_at:
        return {"ok": False, "error": "otp_expired"}

    if otp != code:
        return {"ok": False, "error": "invalid_otp"}

    _best_effort_mark_otp_used(rec)
    token = _best_effort_issue_web_token(phone)
    return {"ok": True, "mode": "real", "token": token}


# ------------------------------------------------------------
# Best-effort storage (never crash the app if tables missing)
# ------------------------------------------------------------

def _best_effort_store_otp(phone: str, otp: str) -> None:
    """
    Table (recommended): web_otps
      - id (uuid)
      - phone (text)
      - otp (text)
      - expires_at (timestamptz)
      - used_at (timestamptz nullable)
      - created_at (timestamptz)
    """
    now = _now_utc()
    expires = now + timedelta(minutes=max(1, OTP_TTL_MINUTES))
    payload = {"phone": phone, "otp": otp, "expires_at": _iso(expires), "created_at": _iso(now)}
    try:
        _table("web_otps").insert(payload).execute()
    except Exception:
        return

def _best_effort_get_latest_otp(phone: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            _table("web_otps")
            .select("*")
            .eq("phone", phone)
            .is_("used_at", None)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None

def _best_effort_mark_otp_used(rec: Dict[str, Any]) -> None:
    try:
        rec_id = rec.get("id")
        if not rec_id:
            return
        _table("web_otps").update({"used_at": _iso(_now_utc())}).eq("id", rec_id).execute()
    except Exception:
        return

def _best_effort_issue_web_token(phone: str) -> str:
    """
    Table (recommended): web_tokens
      - token (text, pk)
      - phone (text)
      - account_id (uuid/text nullable)
      - expires_at (timestamptz)
      - created_at (timestamptz)
      - revoked_at (timestamptz nullable)
    """
    token = os.urandom(24).hex()
    now = _now_utc()
    expires = now + timedelta(days=30)

    payload = {"token": token, "phone": phone, "expires_at": _iso(expires), "created_at": _iso(now)}
    try:
        _table("web_tokens").insert(payload).execute()
    except Exception:
        # still return token; validation wiring can be finalized later
        pass

    return token
