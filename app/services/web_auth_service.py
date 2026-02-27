# app/services/web_auth_service.py
from __future__ import annotations

import os
import time
import secrets
import hashlib
from typing import Any, Dict, Optional, Tuple

from flask import Request

from app.core.supabase_client import get_supabase_client


# -----------------------------
# Exported constants (routes import these)
# -----------------------------
WEB_AUTH_COOKIE_NAME = os.getenv("WEB_SESSION_COOKIE_NAME", "ntg_session")
WEB_AUTH_OTP_TABLE = os.getenv("WEB_OTP_TABLE", "web_otps")
WEB_AUTH_TOKEN_TABLE = os.getenv("WEB_TOKEN_TABLE", "web_tokens")
WEB_AUTH_ACCOUNTS_TABLE = os.getenv("ACCOUNTS_TABLE", "accounts")

OTP_TABLE = WEB_AUTH_OTP_TABLE
TOKEN_TABLE = WEB_AUTH_TOKEN_TABLE
ACCOUNTS_TABLE = WEB_AUTH_ACCOUNTS_TABLE

OTP_PURPOSE_DEFAULT = os.getenv("WEB_OTP_PURPOSE", "web_login")
OTP_TTL_SECONDS = int(os.getenv("WEB_OTP_TTL_SECONDS", "600"))  # 10 mins
OTP_LENGTH = int(os.getenv("WEB_OTP_LENGTH", "6"))
MAX_ATTEMPTS = int(os.getenv("WEB_OTP_MAX_ATTEMPTS", "5"))

SESSION_COOKIE_NAME = WEB_AUTH_COOKIE_NAME

TOKEN_TTL_SECONDS = int(os.getenv("WEB_TOKEN_TTL_SECONDS", "2592000"))  # 30 days
TOKEN_LENGTH_BYTES = int(os.getenv("WEB_TOKEN_BYTES", "32"))

BYPASS_TOKEN = (os.getenv("BYPASS_TOKEN") or "").strip()


# -----------------------------
# Helpers
# -----------------------------
def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _ts_plus(seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _generate_numeric_code(n: int) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(n))


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _extract_bearer(req: Request) -> Optional[str]:
    h = (req.headers.get("Authorization") or "").strip()
    if not h:
        return None
    if h.lower().startswith("bearer "):
        return h.split(" ", 1)[1].strip() or None
    return None


def _extract_dev_bypass(req: Request) -> bool:
    if not BYPASS_TOKEN:
        return False
    bearer = _extract_bearer(req)
    if bearer and bearer == BYPASS_TOKEN:
        return True
    x = (req.headers.get("X-Auth-Token") or "").strip()
    if x and x == BYPASS_TOKEN:
        return True
    return False


def _random_token() -> str:
    # return raw token to client; only store hash in db
    return secrets.token_urlsafe(TOKEN_LENGTH_BYTES)


def _safe_supabase_err(res) -> Optional[str]:
    err = getattr(res, "error", None)
    return str(err) if err else None


# -----------------------------
# OTP API
# -----------------------------
def request_email_otp(
    email: str,
    purpose: str | None = None,
    request_ip: str | None = None,
    device_id: str | None = None,
    user_agent: str | None = None,
) -> Dict[str, Any]:
    """
    Generates OTP, stores hash in DB, returns a server-only _otp_plain so the route can email it.
    """
    sb = get_supabase_client(admin=True)

    contact = (email or "").strip().lower()
    if not contact:
        return {"ok": False, "error": "email_required"}

    purpose = (purpose or OTP_PURPOSE_DEFAULT).strip().lower()

    otp_plain = _generate_numeric_code(OTP_LENGTH)
    code_hash = _sha256_hex(otp_plain)
    expires_at = _ts_plus(OTP_TTL_SECONDS)

    row: Dict[str, Any] = {
        "contact": contact,
        "purpose": purpose,
        "code_hash": code_hash,
        "expires_at": expires_at,
        "used": False,
        "used_at": None,
        "attempts": 0,
        "last_attempt_at": None,
        "locked_until": None,
        "request_ip": request_ip,
        "channel": "email",
    }

    try:
        res = sb.table(OTP_TABLE).insert(row).execute()
        err = _safe_supabase_err(res)
        if err:
            return {"ok": False, "error": "otp_insert_failed", "root_cause": err}
    except Exception as e:
        return {"ok": False, "error": "otp_insert_failed", "root_cause": repr(e)}

    return {
        "ok": True,
        "contact": contact,
        "purpose": purpose,
        "expires_at": expires_at,
        "_otp_plain": otp_plain,  # SERVER-ONLY
        "debug": {
            "tables": {"otp_table": OTP_TABLE, "token_table": TOKEN_TABLE},
            "received": {
                "ip": request_ip,
                "device_id": device_id,
                "user_agent_present": bool(user_agent),
            },
        },
    }


def verify_email_otp(email: str, otp_code: str, purpose: str | None = None) -> Dict[str, Any]:
    sb = get_supabase_client(admin=True)

    contact = (email or "").strip().lower()
    if not contact:
        return {"ok": False, "error": "email_required"}

    otp_code = (otp_code or "").strip()
    if not otp_code:
        return {"ok": False, "error": "otp_required"}

    purpose = (purpose or OTP_PURPOSE_DEFAULT).strip().lower()
    otp_hash = _sha256_hex(otp_code)

    try:
        res = (
            sb.table(OTP_TABLE)
            .select("id, code_hash, expires_at, used, used_at, attempts, locked_until, created_at")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .order("created_at", desc=True)
            .limit(10)
            .execute()
        )
        err = _safe_supabase_err(res)
        if err:
            return {"ok": False, "error": "otp_lookup_failed", "root_cause": err}
        rows = res.data or []
    except Exception as e:
        return {"ok": False, "error": "otp_lookup_failed", "root_cause": repr(e)}

    chosen = None
    for r in rows:
        if r.get("used") is True or r.get("used_at"):
            continue
        if r.get("locked_until"):
            return {"ok": False, "error": "otp_locked", "locked_until": r["locked_until"]}
        chosen = r
        break

    if not chosen:
        return {"ok": False, "error": "otp_not_found"}

    expires_at = (chosen.get("expires_at") or "").strip()
    if expires_at and expires_at < _now_ts():
        return {"ok": False, "error": "otp_expired"}

    if (chosen.get("code_hash") or "") != otp_hash:
        attempts = int(chosen.get("attempts") or 0) + 1
        updates: Dict[str, Any] = {"attempts": attempts, "last_attempt_at": _now_ts()}

        if attempts >= MAX_ATTEMPTS:
            lock_seconds = int(os.getenv("WEB_OTP_LOCK_SECONDS", "600"))
            updates["locked_until"] = _ts_plus(lock_seconds)

        try:
            sb.table(OTP_TABLE).update(updates).eq("id", chosen["id"]).execute()
        except Exception:
            pass

        return {"ok": False, "error": "otp_invalid"}

    try:
        sb.table(OTP_TABLE).update({"used": True, "used_at": _now_ts()}).eq("id", chosen["id"]).execute()
    except Exception as e:
        return {"ok": False, "error": "otp_mark_used_failed", "root_cause": repr(e)}

    return {"ok": True, "contact": contact, "purpose": purpose}


# -----------------------------
# Account + token issuance (MATCHES your schema)
# web_tokens columns: token_hash, account_id, expires_at, revoked, last_seen_at, created_at
# -----------------------------
def _ensure_web_account(contact_email: str) -> Tuple[Optional[str], Optional[str]]:
    sb = get_supabase_client(admin=True)

    provider = "web"
    provider_user_id = contact_email

    try:
        res = (
            sb.table(ACCOUNTS_TABLE)
            .select("id")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
        err = _safe_supabase_err(res)
        if err:
            return None, err

        row = (res.data or [None])[0]
        if row and row.get("id"):
            return row["id"], None

        ins = {
            "provider": provider,
            "provider_user_id": provider_user_id,
            "created_at": _now_ts(),
            "updated_at": _now_ts(),
        }
        res2 = sb.table(ACCOUNTS_TABLE).insert(ins).execute()
        err2 = _safe_supabase_err(res2)
        if err2:
            return None, err2

        row2 = (res2.data or [None])[0]
        if row2 and row2.get("id"):
            return row2["id"], None

        return None, "account_create_failed"
    except Exception as e:
        return None, repr(e)


def _issue_web_token(account_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    sb = get_supabase_client(admin=True)

    token_plain = _random_token()
    token_hash = _sha256_hex(token_plain)
    expires_at = _ts_plus(TOKEN_TTL_SECONDS)

    row = {
        "token_hash": token_hash,
        "account_id": account_id,
        "expires_at": expires_at,
        "revoked": False,
        "last_seen_at": None,
        "created_at": _now_ts(),
    }

    try:
        res = sb.table(TOKEN_TABLE).insert(row).execute()
        err = _safe_supabase_err(res)
        if err:
            return None, None, err
        return token_plain, expires_at, None
    except Exception as e:
        return None, None, repr(e)


def verify_web_otp_and_issue_token(contact: str, otp: str, purpose: str | None = None) -> Dict[str, Any]:
    contact_email = (contact or "").strip().lower()
    if not contact_email:
        return {"ok": False, "error": "contact_required"}

    v = verify_email_otp(contact_email, otp_code=otp, purpose=purpose)
    if not v.get("ok"):
        return v

    account_id, err = _ensure_web_account(contact_email)
    if err or not account_id:
        return {"ok": False, "error": "account_error", "root_cause": err}

    token, expires_at, err2 = _issue_web_token(account_id)
    if err2 or not token:
        return {"ok": False, "error": "token_issue_failed", "root_cause": err2}

    return {
        "ok": True,
        "account_id": account_id,
        "token": token,  # plaintext to client
        "expires_at": expires_at,
        "cookie_name": SESSION_COOKIE_NAME,
    }


def _revoke_token_by_plain(sb, token_plain: str) -> Tuple[bool, Optional[str]]:
    if not token_plain:
        return False, "token_required"
    token_hash = _sha256_hex(token_plain)
    try:
        res = sb.table(TOKEN_TABLE).update({"revoked": True}).eq("token_hash", token_hash).execute()
        err = _safe_supabase_err(res)
        if err:
            return False, err
        return True, None
    except Exception as e:
        return False, repr(e)


def get_account_id_from_request(req: Request) -> Tuple[Optional[str], Dict[str, Any]]:
    debug: Dict[str, Any] = {"cookie": {"name": SESSION_COOKIE_NAME}}

    if _extract_dev_bypass(req):
        debug["source"] = "bypass"
        debug["bypass"] = True
        return None, debug

    sb = get_supabase_client(admin=True)

    def _lookup(token_plain: str, source: str) -> Tuple[Optional[str], Dict[str, Any]]:
        token_hash = _sha256_hex(token_plain)
        debug["source"] = source
        try:
            res = (
                sb.table(TOKEN_TABLE)
                .select("account_id, expires_at, revoked")
                .eq("token_hash", token_hash)
                .limit(1)
                .execute()
            )
            err = _safe_supabase_err(res)
            if err:
                debug["token_error"] = err
                return None, debug

            row = (res.data or [None])[0]
            if not row or not row.get("account_id"):
                return None, debug

            if row.get("revoked") is True:
                debug["revoked"] = True
                return None, debug

            expires_at = (row.get("expires_at") or "").strip()
            if expires_at and expires_at < _now_ts():
                debug["expired"] = True
                return None, debug

            # best-effort update last_seen_at
            try:
                sb.table(TOKEN_TABLE).update({"last_seen_at": _now_ts()}).eq("token_hash", token_hash).execute()
            except Exception:
                pass

            return row["account_id"], debug
        except Exception as e:
            debug["token_error"] = repr(e)
            return None, debug

    bearer = _extract_bearer(req)
    if bearer:
        return _lookup(bearer, "bearer")

    cookie_token = (req.cookies.get(SESSION_COOKIE_NAME) or "").strip()
    if cookie_token:
        return _lookup(cookie_token, "cookie")

    debug["source"] = "none"
    return None, debug


def logout_web_session(req: Request) -> Dict[str, Any]:
    sb = get_supabase_client(admin=True)

    bearer = _extract_bearer(req)
    if bearer:
        ok, err = _revoke_token_by_plain(sb, bearer)
        if not ok and err:
            return {"ok": False, "error": "logout_failed", "root_cause": err}
        return {"ok": True, "logged_out": True, "source": "bearer"}

    cookie_token = (req.cookies.get(SESSION_COOKIE_NAME) or "").strip()
    if cookie_token:
        ok, err = _revoke_token_by_plain(sb, cookie_token)
        if not ok and err:
            return {"ok": False, "error": "logout_failed", "root_cause": err}
        return {"ok": True, "logged_out": True, "source": "cookie"}

    return {"ok": True, "logged_out": True, "source": "none"}


# Backwards-compatible exports expected by routes
def request_web_otp(
    contact: str,
    purpose: str | None = None,
    device_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    **_: Any,
) -> Dict[str, Any]:
    return request_email_otp(contact, purpose=purpose, request_ip=ip, device_id=device_id, user_agent=user_agent)
