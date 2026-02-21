# app/services/web_otp_service.py
from __future__ import annotations

import hashlib
import os
import random
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase

# ------------------------------------------------------------
# ENV / Config
# ------------------------------------------------------------

WEB_AUTH_ENABLED = (os.getenv("WEB_AUTH_ENABLED", "1").strip() == "1")

WEB_OTP_ENABLED = (os.getenv("WEB_OTP_ENABLED", "1").strip() == "1")
WEB_OTP_TTL_MINUTES = int((os.getenv("WEB_OTP_TTL_MINUTES", "10") or "10").strip())
WEB_OTP_LEN = int((os.getenv("WEB_OTP_LEN", "6") or "6").strip())

WEB_OTP_TABLE = (os.getenv("WEB_OTP_TABLE", "web_otps") or "web_otps").strip()
WEB_TOKEN_TABLE = (os.getenv("WEB_TOKEN_TABLE", "web_tokens") or "web_tokens").strip()

WEB_OTP_PEPPER = (os.getenv("WEB_OTP_PEPPER", "") or "").strip()
WEB_TOKEN_PEPPER = (os.getenv("WEB_TOKEN_PEPPER", "") or "").strip()

WEB_SESSION_TTL_DAYS = int((os.getenv("WEB_SESSION_TTL_DAYS", "30") or "30").strip())

# Security controls
WEB_OTP_MAX_ATTEMPTS = int((os.getenv("WEB_OTP_MAX_ATTEMPTS", "5") or "5").strip())

# Rate limits
WEB_OTP_REQ_LIMIT_COUNT = int((os.getenv("WEB_OTP_REQ_LIMIT_COUNT", "3") or "3").strip())
WEB_OTP_REQ_LIMIT_WINDOW_MIN = int((os.getenv("WEB_OTP_REQ_LIMIT_WINDOW_MIN", "15") or "15").strip())

WEB_OTP_IP_LIMIT_COUNT = int((os.getenv("WEB_OTP_IP_LIMIT_COUNT", "20") or "20").strip())
WEB_OTP_IP_LIMIT_WINDOW_MIN = int((os.getenv("WEB_OTP_IP_LIMIT_WINDOW_MIN", "60") or "60").strip())

WEB_OTP_LOCK_MINUTES = int((os.getenv("WEB_OTP_LOCK_MINUTES", "30") or "30").strip())

# Optional dev return
WEB_DEV_RETURN_OTP = (os.getenv("WEB_DEV_RETURN_OTP", "0").strip() == "1")

# ------------------------------------------------------------
# Mail (SMTP)
# Supports both MAIL_* and SMTP_* env names.
# ------------------------------------------------------------

def _env_first(*names: str, default: str = "") -> str:
    for n in names:
        v = os.getenv(n)
        if v is not None and str(v).strip() != "":
            return str(v).strip()
    return default

MAIL_ENABLED = _env_first("MAIL_ENABLED", "SMTP_ENABLED", default="0") == "1"
MAIL_HOST = _env_first("MAIL_HOST", "SMTP_HOST")
MAIL_PORT = int((_env_first("MAIL_PORT", "SMTP_PORT", default="0") or "0").strip() or "0")
MAIL_USER = _env_first("MAIL_USER", "SMTP_USER")
MAIL_PASS = _env_first("MAIL_PASS", "SMTP_PASS")
MAIL_FROM_EMAIL = _env_first("MAIL_FROM_EMAIL", default="no-reply@thecre8hub.com")
MAIL_FROM_NAME = _env_first("MAIL_FROM_NAME", default="NaijaTax Guide")
MAIL_USE_TLS = _env_first("MAIL_USE_TLS", default="1") == "1"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _sb():
    try:
        return supabase()
    except TypeError:
        return supabase

def _table(name: str):
    return _sb().table(name)

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(v).astimezone(timezone.utc)
    except Exception:
        return None

def _clean(v: Any) -> str:
    return (v or "").strip()

def _normalize_contact(v: str) -> str:
    v = _clean(v)
    if not v:
        return ""
    if "@" in v:
        return v.lower()
    if v.startswith("0"):
        return "+234" + v[1:]
    if v.startswith("234"):
        return "+" + v
    return v

def _is_email(v: str) -> bool:
    v = _clean(v)
    return ("@" in v) and ("." in v)

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _otp_hash(contact: str, purpose: str, otp: str) -> str:
    # ties OTP to contact+purpose + pepper
    return _sha256_hex(f"{WEB_OTP_PEPPER}:{contact}:{purpose}:{otp}")

def _token_hash(raw_token: str) -> str:
    # MUST match app/core/auth.py: sha256(f"{pepper}:{raw_token}")
    return _sha256_hex(f"{WEB_TOKEN_PEPPER}:{raw_token}")

def _gen_otp() -> str:
    low = 10 ** (WEB_OTP_LEN - 1)
    high = (10 ** WEB_OTP_LEN) - 1
    return str(random.randint(low, high))

def smtp_is_configured() -> bool:
    if not MAIL_ENABLED:
        return False
    if not MAIL_HOST or not MAIL_PORT or not MAIL_USER or not MAIL_PASS:
        return False
    return True

def _send_email_otp(to_email: str, otp: str, ttl_minutes: int) -> Tuple[bool, Optional[str]]:
    if not smtp_is_configured():
        return False, "smtp_not_configured"

    msg = EmailMessage()
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM_EMAIL}>"
    msg["To"] = to_email
    msg["Subject"] = f"Your NaijaTax Guide login code: {otp}"

    msg.set_content(
        "Your NaijaTax Guide one-time login code is:\n\n"
        f"{otp}\n\n"
        f"This code expires in {ttl_minutes} minutes.\n\n"
        "If you did not request this code, ignore this email."
    )

    try:
        with smtplib.SMTP(MAIL_HOST, MAIL_PORT, timeout=15) as server:
            if MAIL_USE_TLS:
                server.starttls()
            server.login(MAIL_USER, MAIL_PASS)
            server.send_message(msg)
        return True, None
    except Exception as e:
        return False, f"smtp_send_failed:{type(e).__name__}"

# ------------------------------------------------------------
# Rate limiting + lock checks
# ------------------------------------------------------------

def _latest_otp_row(contact: str, purpose: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            _table(WEB_OTP_TABLE)
            .select("id, created_at, expires_at, used, attempts, locked_until")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None

def _is_locked(contact: str, purpose: str) -> Tuple[bool, Optional[str]]:
    row = _latest_otp_row(contact, purpose)
    if not row:
        return False, None
    locked_until = _parse_iso(row.get("locked_until"))
    if locked_until and _now_utc() < locked_until:
        # still locked
        return True, f"locked_until:{_iso(locked_until)}"
    return False, None

def _count_recent_requests_by_contact(contact: str, purpose: str, window_min: int) -> int:
    since = _now_utc() - timedelta(minutes=max(1, int(window_min)))
    try:
        res = (
            _table(WEB_OTP_TABLE)
            .select("id, created_at")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .gte("created_at", _iso(since))
            .limit(500)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return len(rows)
    except Exception:
        return 0

def _count_recent_requests_by_ip(ip: str, window_min: int) -> int:
    if not ip:
        return 0
    since = _now_utc() - timedelta(minutes=max(1, int(window_min)))
    try:
        res = (
            _table(WEB_OTP_TABLE)
            .select("id, created_at")
            .eq("request_ip", ip)
            .gte("created_at", _iso(since))
            .limit(1000)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return len(rows)
    except Exception:
        return 0

def _lock_contact(contact: str, purpose: str, minutes: int) -> None:
    # Best effort: mark the latest row with locked_until (so both request/verify can block)
    row = _latest_otp_row(contact, purpose)
    if not row or not row.get("id"):
        return
    locked_until = _now_utc() + timedelta(minutes=max(1, int(minutes)))
    try:
        _table(WEB_OTP_TABLE).update({"locked_until": _iso(locked_until)}).eq("id", row["id"]).execute()
    except Exception:
        return

# ------------------------------------------------------------
# Accounts + tokens
# ------------------------------------------------------------

def _upsert_account_for_contact(contact: str) -> Optional[str]:
    """
    provider='web', provider_user_id=contact
    """
    try:
        res = (
            _sb()
            .table("accounts")
            .select("account_id")
            .eq("provider", "web")
            .eq("provider_user_id", contact)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows:
            return rows[0].get("account_id")

        ins = (
            _sb()
            .table("accounts")
            .insert({
                "provider": "web",
                "provider_user_id": contact,
                "display_name": contact,
                "phone": contact,
            })
            .execute()
        )
        inserted = ins.data or []
        return inserted[0].get("account_id") if inserted else None
    except Exception:
        return None

def _issue_web_session_token(account_id: str, contact: str) -> Dict[str, Any]:
    raw_token = os.urandom(24).hex()
    now = _now_utc()
    expires = now + timedelta(days=max(1, int(WEB_SESSION_TTL_DAYS)))

    payload = {
        "token_hash": _token_hash(raw_token),
        "account_id": account_id,
        "expires_at": _iso(expires),
        "revoked": False,
        "last_seen_at": _iso(now),
        "created_at": _iso(now),
    }

    # optional contact column
    if _has_column(WEB_TOKEN_TABLE, "contact"):
        payload["contact"] = contact

    _table(WEB_TOKEN_TABLE).insert(payload).execute()
    return {"token": raw_token, "account_id": account_id, "expires_at": _iso(expires)}

def _has_column(table: str, col: str) -> bool:
    try:
        _table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False

# ------------------------------------------------------------
# OTP Storage
# ------------------------------------------------------------

def _create_otp_row(
    contact: str,
    purpose: str,
    otp: str,
    request_ip: str,
    dest_email: Optional[str],
    email_sent: bool,
    email_error: Optional[str],
) -> None:
    now = _now_utc()
    expires = now + timedelta(minutes=max(1, int(WEB_OTP_TTL_MINUTES)))

    payload: Dict[str, Any] = {
        "contact": contact,
        "purpose": purpose,
        "code_hash": _otp_hash(contact, purpose, otp),
        "expires_at": _iso(expires),
        "used": False,
        "attempts": 0,
        "locked_until": None,
        "request_ip": request_ip or None,
        "created_at": _iso(now),
    }

    # optional metadata columns
    if _has_column(WEB_OTP_TABLE, "sent_to"):
        payload["sent_to"] = dest_email
    if _has_column(WEB_OTP_TABLE, "channel"):
        payload["channel"] = "email" if dest_email else "none"
    if _has_column(WEB_OTP_TABLE, "email_sent"):
        payload["email_sent"] = bool(email_sent)
    if _has_column(WEB_OTP_TABLE, "email_error"):
        payload["email_error"] = email_error

    _table(WEB_OTP_TABLE).insert(payload).execute()

def _find_latest_active_otp(contact: str, purpose: str) -> Optional[Dict[str, Any]]:
    """
    Latest unused, unexpired OTP row for contact+purpose.
    """
    try:
        res = (
            _table(WEB_OTP_TABLE)
            .select("id, code_hash, expires_at, used, attempts, locked_until, created_at")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .eq("used", False)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return None

        row = rows[0]
        exp = _parse_iso(row.get("expires_at"))
        if not exp or _now_utc() > exp:
            return None

        locked_until = _parse_iso(row.get("locked_until"))
        if locked_until and _now_utc() < locked_until:
            return row  # still active but locked

        return row
    except Exception:
        return None

def _increment_attempts_and_maybe_lock(row_id: str, attempts: int) -> None:
    """
    attempts passed in is current attempts; we increment to next.
    If next > WEB_OTP_MAX_ATTEMPTS => mark used + lock contact.
    """
    next_attempts = int(attempts or 0) + 1
    updates: Dict[str, Any] = {
        "attempts": next_attempts,
        "last_attempt_at": _iso(_now_utc()),
    } if _has_column(WEB_OTP_TABLE, "last_attempt_at") else {"attempts": next_attempts}

    # If exceeded, invalidate and lock
    if next_attempts >= WEB_OTP_MAX_ATTEMPTS:
        updates["used"] = True
        if _has_column(WEB_OTP_TABLE, "used_at"):
            updates["used_at"] = _iso(_now_utc())
        locked_until = _now_utc() + timedelta(minutes=max(1, int(WEB_OTP_LOCK_MINUTES)))
        updates["locked_until"] = _iso(locked_until)

    try:
        _table(WEB_OTP_TABLE).update(updates).eq("id", row_id).execute()
    except Exception:
        return

def _mark_used(row_id: str) -> None:
    updates: Dict[str, Any] = {"used": True}
    if _has_column(WEB_OTP_TABLE, "used_at"):
        updates["used_at"] = _iso(_now_utc())
    try:
        _table(WEB_OTP_TABLE).update(updates).eq("id", row_id).execute()
    except Exception:
        return

# ------------------------------------------------------------
# Public API used by web_auth routes
# ------------------------------------------------------------

def request_web_login_otp(
    contact: str,
    purpose: str = "web_login",
    request_ip: str = "",
    email_to: str = "",
) -> Dict[str, Any]:
    """
    Generates + stores OTP. Sends email when possible.

    Security:
    - Blocks when locked
    - Contact-based request rate limit
    - IP-based request rate limit
    """
    if not WEB_AUTH_ENABLED:
        return {"ok": False, "error": "web_auth_disabled"}

    contact = _normalize_contact(contact)
    purpose = _clean(purpose) or "web_login"
    request_ip = _clean(request_ip)

    if not contact:
        return {"ok": False, "error": "missing_contact"}

    # Lock check
    locked, lock_reason = _is_locked(contact, purpose)
    if locked:
        return {"ok": False, "error": "locked", "detail": lock_reason}

    # Rate limit (contact)
    c = _count_recent_requests_by_contact(contact, purpose, WEB_OTP_REQ_LIMIT_WINDOW_MIN)
    if c >= WEB_OTP_REQ_LIMIT_COUNT:
        _lock_contact(contact, purpose, WEB_OTP_LOCK_MINUTES)
        return {"ok": False, "error": "rate_limited", "scope": "contact"}

    # Rate limit (IP)
    if request_ip:
        ip_c = _count_recent_requests_by_ip(request_ip, WEB_OTP_IP_LIMIT_WINDOW_MIN)
        if ip_c >= WEB_OTP_IP_LIMIT_COUNT:
            return {"ok": False, "error": "rate_limited", "scope": "ip"}

    # Generate OTP
    otp = _gen_otp() if WEB_OTP_ENABLED else (os.getenv("WEB_OTP_STUB_CODE", "123456").strip() or "123456")
    ttl = WEB_OTP_TTL_MINUTES

    # Determine email destination
    email_to = _clean(email_to).lower()
    dest_email = ""
    if _is_email(contact):
        dest_email = contact
    elif _is_email(email_to):
        dest_email = email_to

    email_sent = False
    email_error: Optional[str] = None
    if dest_email:
        email_sent, email_error = _send_email_otp(dest_email, otp, ttl)

    # Store OTP row
    try:
        _create_otp_row(
            contact=contact,
            purpose=purpose,
            otp=otp,
            request_ip=request_ip,
            dest_email=dest_email or None,
            email_sent=email_sent,
            email_error=email_error,
        )
    except Exception:
        # Do not leak internals; caller can retry
        return {"ok": False, "error": "otp_store_failed"}

    resp: Dict[str, Any] = {
        "ok": True,
        "ttl_minutes": ttl,
        "email_sent": bool(email_sent),
        "email_to": dest_email or None,
    }
    if dest_email and email_error:
        resp["email_error"] = email_error

    if WEB_DEV_RETURN_OTP:
        resp["dev_otp"] = otp
        resp["smtp_configured"] = smtp_is_configured()

    return resp


def verify_web_login_otp(
    contact: str,
    otp: str,
    purpose: str = "web_login",
    request_ip: str = "",
) -> Dict[str, Any]:
    """
    Verifies OTP and returns a web session token.

    Security:
    - Locks respected
    - Uses latest active OTP row for contact+purpose
    - Wrong OTP increments attempts
    - attempts >= WEB_OTP_MAX_ATTEMPTS => invalidates + locks
    """
    if not WEB_AUTH_ENABLED:
        return {"ok": False, "error": "web_auth_disabled"}

    contact = _normalize_contact(contact)
    otp = _clean(otp)
    purpose = _clean(purpose) or "web_login"
    request_ip = _clean(request_ip)

    if not contact or not otp:
        return {"ok": False, "error": "missing_contact_or_otp"}

    # Lock check
    locked, lock_reason = _is_locked(contact, purpose)
    if locked:
        return {"ok": False, "error": "locked", "detail": lock_reason}

    row = _find_latest_active_otp(contact, purpose)
    if not row:
        # nothing active to validate against
        return {"ok": False, "error": "invalid_otp"}

    # if row shows lock
    locked_until = _parse_iso(row.get("locked_until"))
    if locked_until and _now_utc() < locked_until:
        return {"ok": False, "error": "locked", "detail": f"locked_until:{_iso(locked_until)}"}

    row_id = row.get("id")
    if not row_id:
        return {"ok": False, "error": "invalid_otp"}

    expected = (row.get("code_hash") or "").strip()
    got = _otp_hash(contact, purpose, otp)

    if not expected or got != expected:
        # wrong otp -> increment attempts on the active row
        _increment_attempts_and_maybe_lock(row_id, int(row.get("attempts") or 0))
        return {"ok": False, "error": "invalid_otp"}

    # Correct OTP -> mark used
    _mark_used(row_id)

    # Ensure account
    account_id = _upsert_account_for_contact(contact)
    if not account_id:
        return {"ok": False, "error": "account_create_failed"}

    # Issue session token
    try:
        token_info = _issue_web_session_token(account_id=account_id, contact=contact)
        return {"ok": True, **token_info}
    except Exception:
        return {"ok": False, "error": "token_issue_failed"}
