# app/services/web_otp_service.py
from __future__ import annotations

import os
import random
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, List

from ..core.supabase_client import supabase


# ------------------------------------------------------------
# Config
# ------------------------------------------------------------

# OTP enable switch (if off, we still store + return stub OTP to keep login moving)
WEB_OTP_ENABLED = (os.getenv("WEB_OTP_ENABLED", "0").strip() == "1")

WEB_OTP_TTL_MINUTES = int((os.getenv("WEB_OTP_TTL_MINUTES", "10") or "10").strip())
WEB_OTP_LEN = int((os.getenv("WEB_OTP_LEN", "6") or "6").strip())

# For stub/dev testing (when WEB_OTP_ENABLED=0)
WEB_OTP_STUB_CODE = (os.getenv("WEB_OTP_STUB_CODE", "123456") or "123456").strip()

# Return OTP in API response (dev convenience). MUST be 0 in prod.
WEB_DEV_RETURN_OTP = (os.getenv("WEB_DEV_RETURN_OTP", "0").strip() == "1")

# Session token TTL (how long web session stays valid after login)
WEB_SESSION_TTL_DAYS = int((os.getenv("WEB_SESSION_TTL_DAYS", "30") or "30").strip())

# Mail (SMTP)
MAIL_ENABLED = (os.getenv("MAIL_ENABLED", "0").strip() == "1")
MAIL_HOST = (os.getenv("MAIL_HOST", "") or "").strip()
MAIL_PORT = int((os.getenv("MAIL_PORT", "0") or "0").strip() or "0")
MAIL_USER = (os.getenv("MAIL_USER", "") or "").strip()
MAIL_PASS = (os.getenv("MAIL_PASS", "") or "").strip()
MAIL_FROM_EMAIL = (os.getenv("MAIL_FROM_EMAIL", "") or "").strip()
MAIL_FROM_NAME = (os.getenv("MAIL_FROM_NAME", "NaijaTax Guide") or "NaijaTax Guide").strip()

# Typical SMTP behavior: STARTTLS on 587/2525
MAIL_USE_TLS = (os.getenv("MAIL_USE_TLS", "1").strip() == "1")
MAIL_USE_SSL = (os.getenv("MAIL_USE_SSL", "0").strip() == "1")

# Optional: set to "1" to include config diagnostics in response (safe: no secrets)
MAIL_DEBUG = (os.getenv("MAIL_DEBUG", "1").strip() == "1")


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
        v = str(value).replace("Z", "+00:00")
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

def _is_email(s: str) -> bool:
    s = (s or "").strip()
    return ("@" in s) and ("." in s)

def _gen_otp() -> str:
    low = 10 ** (WEB_OTP_LEN - 1)
    high = (10 ** WEB_OTP_LEN) - 1
    return str(random.randint(low, high))

def _smtp_missing() -> List[str]:
    missing = []
    if not MAIL_HOST:
        missing.append("MAIL_HOST")
    if not MAIL_PORT:
        missing.append("MAIL_PORT")
    if not MAIL_USER:
        missing.append("MAIL_USER")
    if not MAIL_PASS:
        missing.append("MAIL_PASS")
    if not MAIL_FROM_EMAIL:
        missing.append("MAIL_FROM_EMAIL")
    return missing

def _smtp_configured() -> bool:
    return MAIL_ENABLED and (len(_smtp_missing()) == 0)


def _send_otp_email(to_email: str, otp: str, ttl_minutes: int) -> Dict[str, Any]:
    """
    Sends OTP email using SMTP.
    Returns:
      { ok: bool, error?: str }
    """
    if not _smtp_configured():
        return {"ok": False, "error": "smtp_not_configured"}

    subject = "Your NaijaTax Guide login code"
    body = (
        f"Your One-Time Password (OTP) is: {otp}\n\n"
        f"This code expires in {ttl_minutes} minute(s).\n\n"
        f"If you did not request this, you can ignore this email."
    )

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM_EMAIL}>"
    msg["To"] = to_email
    msg.set_content(body)

    try:
        if MAIL_USE_SSL:
            with smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT, timeout=20) as server:
                if MAIL_USER and MAIL_PASS:
                    server.login(MAIL_USER, MAIL_PASS)
                server.send_message(msg)
        else:
            with smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=20) as server:
                server.ehlo()
                if MAIL_USE_TLS:
                    server.starttls()
                    server.ehlo()
                if MAIL_USER and MAIL_PASS:
                    server.login(MAIL_USER, MAIL_PASS)
                server.send_message(msg)

        return {"ok": True}
    except Exception as e:
        # Don't leak secrets; error text is still useful for diagnosing.
        return {"ok": False, "error": f"smtp_send_failed:{type(e).__name__}:{str(e)[:200]}"}


# ------------------------------------------------------------
# Public API (MUST match app/routes/web_auth.py)
# ------------------------------------------------------------

def request_web_login_otp(contact: str, purpose: str = "web_login") -> Dict[str, Any]:
    """
    Generates + stores OTP for a web login flow.

    Returns:
      { ok: True, ttl_minutes, mode, email_sent?, email_error?, smtp_missing? }
      and optionally dev_otp if WEB_DEV_RETURN_OTP=1
    """
    contact = _clean(contact)
    purpose = _clean(purpose) or "web_login"
    if not contact:
        return {"ok": False, "error": "missing_contact"}

    # Choose OTP
    if not WEB_OTP_ENABLED:
        otp = WEB_OTP_STUB_CODE
        mode = "stub"
    else:
        otp = _gen_otp()
        mode = "real"

    # Always store best-effort (so verify can work)
    _best_effort_store_otp(contact=contact, purpose=purpose, otp=otp)

    # Email if contact is email
    email_sent = False
    email_error = None

    if _is_email(contact):
        send_res = _send_otp_email(to_email=contact, otp=otp, ttl_minutes=WEB_OTP_TTL_MINUTES)
        email_sent = bool(send_res.get("ok"))
        email_error = (send_res.get("error") if not email_sent else None)

    resp: Dict[str, Any] = {
        "ok": True,
        "mode": mode,
        "ttl_minutes": WEB_OTP_TTL_MINUTES,
    }

    if _is_email(contact):
        resp.update({
            "email_to": contact,
            "email_sent": email_sent,
            "email_error": email_error,
        })

    # Expose root-cause safely (NO secrets)
    if MAIL_DEBUG:
        resp["mail_enabled"] = MAIL_ENABLED
        resp["smtp_configured"] = _smtp_configured()
        resp["smtp_missing"] = _smtp_missing()

    # Only include dev_otp when explicitly enabled
    if WEB_DEV_RETURN_OTP:
        resp["dev_otp"] = otp

    return resp


def verify_web_login_otp(contact: str, otp: str, purpose: str = "web_login") -> Dict[str, Any]:
    """
    Verifies OTP and returns a web session token.
    Returns:
      { ok: True, token: "...", mode: "stub"|"real" }
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
        pass

    return token
