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

# If disabled, OTP works in stub mode to keep web login moving.
WEB_OTP_ENABLED = (os.getenv("WEB_OTP_ENABLED", "0").strip() == "1")

WEB_OTP_TTL_MINUTES = int((os.getenv("WEB_OTP_TTL_MINUTES", "10") or "10").strip())
WEB_OTP_LEN = int((os.getenv("WEB_OTP_LEN", "6") or "6").strip())

# For stub/dev testing (when WEB_OTP_ENABLED=0)
WEB_OTP_STUB_CODE = (os.getenv("WEB_OTP_STUB_CODE", "123456") or "123456").strip()

# Session token TTL (how long web session stays valid after login)
WEB_SESSION_TTL_DAYS = int((os.getenv("WEB_SESSION_TTL_DAYS", "30") or "30").strip())


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

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

def _clean(s: Any) -> str:
    return (s or "").strip()

def _gen_otp() -> str:
    low = 10 ** (WEB_OTP_LEN - 1)
    high = (10 ** WEB_OTP_LEN) - 1
    return str(random.randint(low, high))


# ------------------------------------------------------------
# Public API (MUST match app/routes/web_auth.py)
# ------------------------------------------------------------

def request_web_login_otp(contact: str, purpose: str = "web_login") -> Dict[str, Any]:
    """
    Generates + stores OTP for a web login flow.

    Expected by routes:
      request_web_login_otp(contact=..., purpose=...)

    Returns (DEV friendly):
      { ok: True, dev_otp?: "123456" }

    In prod, route never returns dev_otp anyway (your web_auth.py enforces that).
    """
    contact = _clean(contact)
    purpose = _clean(purpose) or "web_login"
    if not contact:
        return {"ok": False, "error": "missing_contact"}

    # Stub mode (no OTP infrastructure required)
    if not WEB_OTP_ENABLED:
        _best_effort_store_otp(contact=contact, purpose=purpose, otp=WEB_OTP_STUB_CODE)
        return {"ok": True, "mode": "stub", "dev_otp": WEB_OTP_STUB_CODE, "ttl_minutes": WEB_OTP_TTL_MINUTES}

    otp = _gen_otp()
    _best_effort_store_otp(contact=contact, purpose=purpose, otp=otp)

    # In a real deployment, you'd send OTP via SMS/WhatsApp here.
    # This service intentionally only generates/stores to keep it modular.
    return {"ok": True, "mode": "real", "ttl_minutes": WEB_OTP_TTL_MINUTES}


def verify_web_login_otp(contact: str, otp: str, purpose: str = "web_login") -> Dict[str, Any]:
    """
    Verifies OTP and returns a web session token.

    Expected by routes:
      verify_web_login_otp(contact=..., otp=..., purpose=...)

    Returns:
      { ok: True, token: "...", account_id?: "...", mode: "stub"|"real" }
    """
    contact = _clean(contact)
    otp = _clean(otp)
    purpose = _clean(purpose) or "web_login"

    if not contact or not otp:
        return {"ok": False, "error": "missing_contact_or_otp"}

    # Stub mode (accept fixed OTP)
    if not WEB_OTP_ENABLED:
        if otp != WEB_OTP_STUB_CODE:
            return {"ok": False, "error": "invalid_otp"}
        token = _issue_web_session_token(contact=contact)
        return {"ok": True, "mode": "stub", "token": token}

    rec = _best_effort_get_latest_otp(contact=contact, purpose=purpose)
    if not rec:
        return {"ok": False, "error": "otp_not_found"}

    code = _clean(rec.get("otp"))
    expires_at = _parse_iso(rec.get("expires_at"))

    if not code or not expires_at:
        return {"ok": False, "error": "otp_record_invalid"}

    if _now_utc() > expires_at:
        return {"ok": False, "error": "otp_expired"}

    if otp != code:
        return {"ok": False, "error": "invalid_otp"}

    _best_effort_mark_otp_used(rec)

    token = _issue_web_session_token(contact=contact)
    return {"ok": True, "mode": "real", "token": token}


# ------------------------------------------------------------
# Storage (best effort - never crash boot)
# Recommended tables:
#   web_otps(contact, purpose, otp, expires_at, used_at, created_at)
#   web_sessions(token, contact, account_id, expires_at, created_at, last_seen_at, revoked_at)
# ------------------------------------------------------------

def _best_effort_store_otp(contact: str, purpose: str, otp: str) -> None:
    now = _now_utc()
    expires = now + timedelta(minutes=max(1, int(WEB_OTP_TTL_MINUTES)))

    payload = {
        "contact": contact,
        "purpose": purpose,
        "otp": otp,
        "expires_at": _iso(expires),
        "created_at": _iso(now),
    }

    try:
        _table("web_otps").insert(payload).execute()
    except Exception:
        return


def _best_effort_get_latest_otp(contact: str, purpose: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            _table("web_otps")
            .select("*")
            .eq("contact", contact)
            .eq("purpose", purpose)
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


def _issue_web_session_token(contact: str) -> str:
    """
    Creates a web session token and stores in web_sessions best-effort.
    """
    token = os.urandom(24).hex()
    now = _now_utc()
    expires = now + timedelta(days=max(1, int(WEB_SESSION_TTL_DAYS)))

    payload = {
        "token": token,
        "contact": contact,
        "expires_at": _iso(expires),
        "created_at": _iso(now),
        "last_seen_at": _iso(now),
    }

    try:
        _table("web_sessions").insert(payload).execute()
    except Exception:
        # Still return token; validation service can be strict later
        pass

    return token
