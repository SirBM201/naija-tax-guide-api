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

# Internal aliases
OTP_TABLE = WEB_AUTH_OTP_TABLE
TOKEN_TABLE = WEB_AUTH_TOKEN_TABLE
ACCOUNTS_TABLE = WEB_AUTH_ACCOUNTS_TABLE

OTP_PURPOSE_DEFAULT = os.getenv("WEB_OTP_PURPOSE", "web_login")
OTP_TTL_SECONDS = int(os.getenv("WEB_OTP_TTL_SECONDS", "600"))  # 10 mins
OTP_LENGTH = int(os.getenv("WEB_OTP_LENGTH", "6"))
MAX_ATTEMPTS = int(os.getenv("WEB_OTP_MAX_ATTEMPTS", "5"))

SESSION_COOKIE_NAME = WEB_AUTH_COOKIE_NAME

# Token settings
TOKEN_TTL_SECONDS = int(os.getenv("WEB_TOKEN_TTL_SECONDS", "2592000"))  # 30 days
TOKEN_LENGTH_BYTES = int(os.getenv("WEB_TOKEN_BYTES", "32"))

# Dev bypass (optional)
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
    """
    Matches your prior behavior:
      - Authorization: Bearer <BYPASS_TOKEN>
      - X-Auth-Token: <BYPASS_TOKEN>
    """
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
    # URL-safe token, stable length
    return secrets.token_urlsafe(TOKEN_LENGTH_BYTES)


def _revoke_token(sb, token: str) -> Tuple[bool, Optional[str]]:
    """
    Best-effort revoke: set revoked_at. If table doesn't have revoked_at,
    update will fail; we surface the root cause for debugging.
    """
    if not token:
        return False, "token_required"
    try:
        res = sb.table(TOKEN_TABLE).update({"revoked_at": _now_ts()}).eq("token", token).execute()
        if getattr(res, "error", None):
            return False, str(res.error)
        return True, None
    except Exception as e:
        return False, repr(e)


# -----------------------------
# OTP API
# -----------------------------
def request_email_otp(email: str, purpose: str | None = None, request_ip: str | None = None) -> Dict[str, Any]:
    sb = get_supabase_client(admin=True)

    contact = (email or "").strip().lower()
    if not contact:
        return {"ok": False, "error": "email_required"}

    purpose = (purpose or OTP_PURPOSE_DEFAULT).strip().lower()

    otp_plain = _generate_numeric_code(OTP_LENGTH)
    code_hash = _sha256_hex(otp_plain)
    expires_at = _ts_plus(OTP_TTL_SECONDS)

    row = {
        "contact": contact,
        "purpose": purpose,
        "code_hash": code_hash,
        "code_plain": None,  # keep null in prod
        "expires_at": expires_at,
        "used": False,
        "used_at": None,
        "attempts": 0,
        "last_attempt_at": None,
        "locked_until": None,
        "request_ip": request_ip,
        "sent_to": contact,
        "channel": "email",
        "email_sent": None,
        "email_error": None,
        "otp_code": None,  # legacy
        "phone_e164": None,
    }

    try:
        res = sb.table(OTP_TABLE).insert(row).execute()
        if getattr(res, "error", None):
            return {"ok": False, "error": "otp_insert_failed", "root_cause": str(res.error)}
    except Exception as e:
        return {"ok": False, "error": "otp_insert_failed", "root_cause": repr(e)}

    dev_return_plain = _truthy(os.getenv("WEB_OTP_RETURN_PLAIN"))

    out: Dict[str, Any] = {
        "ok": True,
        "contact": contact,
        "purpose": purpose,
        "expires_at": expires_at,
        "debug": {
            "cookie": {"name": SESSION_COOKIE_NAME},
            "tables": {"otp_table": OTP_TABLE, "token_table": TOKEN_TABLE},
        },
    }
    if dev_return_plain:
        out["otp"] = otp_plain  # DEV ONLY
    return out


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
        if getattr(res, "error", None):
            return {"ok": False, "error": "otp_lookup_failed", "root_cause": str(res.error)}
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
# Account + token issuance
# -----------------------------
def _ensure_web_account(contact_email: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Ensures an accounts row exists for this web user.
    Returns (account_id, error).
    """
    sb = get_supabase_client(admin=True)

    provider = "web"
    provider_user_id = contact_email  # stable mapping

    try:
        res = (
            sb.table(ACCOUNTS_TABLE)
            .select("id")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
        if getattr(res, "error", None):
            return None, str(res.error)

        row = (res.data or [None])[0]
        if row and row.get("id"):
            return row["id"], None

        ins = {
            "provider": provider,
            "provider_user_id": provider_user_id,
            "display_name": None,
            "phone": None,
            "email": contact_email,
            "created_at": _now_ts(),
            "updated_at": _now_ts(),
        }
        res2 = sb.table(ACCOUNTS_TABLE).insert(ins).execute()
        if getattr(res2, "error", None):
            return None, str(res2.error)

        row2 = (res2.data or [None])[0]
        if row2 and row2.get("id"):
            return row2["id"], None

        res3 = (
            sb.table(ACCOUNTS_TABLE)
            .select("id")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
        if getattr(res3, "error", None):
            return None, str(res3.error)
        row3 = (res3.data or [None])[0]
        if row3 and row3.get("id"):
            return row3["id"], None

        return None, "account_create_failed"
    except Exception as e:
        return None, repr(e)


def _issue_web_token(account_id: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Inserts a token into web_tokens and returns (token, expires_at, error).
    """
    sb = get_supabase_client(admin=True)

    token = _random_token()
    expires_at = _ts_plus(TOKEN_TTL_SECONDS)

    row = {
        "token": token,
        "account_id": account_id,
        "created_at": _now_ts(),
        "expires_at": expires_at,
        "revoked_at": None,
    }

    try:
        res = sb.table(TOKEN_TABLE).insert(row).execute()
        if getattr(res, "error", None):
            return None, None, str(res.error)
        return token, expires_at, None
    except Exception as e:
        return None, None, repr(e)


def verify_web_otp_and_issue_token(contact: str, otp: str, purpose: str | None = None) -> Dict[str, Any]:
    """
    REQUIRED by app.routes.web_auth.
    Flow: verify OTP -> ensure web account -> issue token.
    """
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
        "token": token,
        "expires_at": expires_at,
        "cookie_name": SESSION_COOKIE_NAME,
    }


# -----------------------------
# REQUIRED by routes: logout
# -----------------------------
def logout_web_session(req: Request) -> Dict[str, Any]:
    """
    REQUIRED by app.routes.web_auth.

    Behavior:
      - If Bearer token exists -> revoke it in web_tokens
      - Else if session cookie exists -> revoke it in web_tokens
      - Else return ok (idempotent logout)
    """
    sb = get_supabase_client(admin=True)

    bearer = _extract_bearer(req)
    if bearer:
        ok, err = _revoke_token(sb, bearer)
        if not ok and err:
            return {"ok": False, "error": "logout_failed", "root_cause": err}
        return {"ok": True, "logged_out": True, "source": "bearer"}

    cookie_token = (req.cookies.get(SESSION_COOKIE_NAME) or "").strip()
    if cookie_token:
        ok, err = _revoke_token(sb, cookie_token)
        if not ok and err:
            return {"ok": False, "error": "logout_failed", "root_cause": err}
        return {"ok": True, "logged_out": True, "source": "cookie"}

    return {"ok": True, "logged_out": True, "source": "none"}


# -----------------------------
# Backwards-compatible exports expected by routes
# -----------------------------
def request_web_otp(contact: str, purpose: str | None = None, request_ip: str | None = None) -> Dict[str, Any]:
    return request_email_otp(contact, purpose=purpose, request_ip=request_ip)


def verify_web_otp(contact: str, otp: str, purpose: str | None = None) -> Dict[str, Any]:
    return verify_email_otp(contact, otp_code=otp, purpose=purpose)


# -----------------------------
# Auth resolver used by /ask
# -----------------------------
def get_account_id_from_request(req: Request) -> Tuple[Optional[str], Dict[str, Any]]:
    debug: Dict[str, Any] = {"cookie": {"name": SESSION_COOKIE_NAME}}

    try:
        body = req.get_json(silent=True) or {}
    except Exception:
        body = {}
    if isinstance(body, dict):
        aid = (body.get("account_id") or "").strip()
        if aid:
            debug["source"] = "body.account_id"
            return aid, debug

    if _extract_dev_bypass(req):
        debug["source"] = "bypass"
        debug["bypass"] = True
        return None, debug

    sb = get_supabase_client(admin=True)

    bearer = _extract_bearer(req)
    if bearer:
        debug["source"] = "bearer"
        debug["token_prefix"] = bearer[:8]
        try:
            res = (
                sb.table(TOKEN_TABLE)
                .select("account_id, expires_at, revoked_at")
                .eq("token", bearer)
                .limit(1)
                .execute()
            )
            if getattr(res, "error", None):
                debug["token_error"] = str(res.error)
            else:
                row = (res.data or [None])[0]
                if row and row.get("account_id"):
                    return row["account_id"], debug
        except Exception as e:
            debug["token_error"] = repr(e)

    cookie_token = (req.cookies.get(SESSION_COOKIE_NAME) or "").strip()
    if cookie_token:
        debug["source"] = "cookie"
        debug["cookie_present"] = True
        try:
            res = (
                sb.table(TOKEN_TABLE)
                .select("account_id, expires_at, revoked_at")
                .eq("token", cookie_token)
                .limit(1)
                .execute()
            )
            if getattr(res, "error", None):
                debug["cookie_error"] = str(res.error)
            else:
                row = (res.data or [None])[0]
                if row and row.get("account_id"):
                    return row["account_id"], debug
        except Exception as e:
            debug["cookie_error"] = repr(e)

    xaid = (req.headers.get("X-Account-Id") or "").strip()
    if xaid:
        debug["source"] = "header:X-Account-Id"
        return xaid, debug

    debug["source"] = "none"
    return None, debug
