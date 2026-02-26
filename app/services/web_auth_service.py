from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from app.core.supabase_client import supabase


# --------------------------------------------------
# Time helpers
# --------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


# --------------------------------------------------
# Env helpers (NO app.core.config imports, to prevent boot crashes)
# --------------------------------------------------
def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


WEB_AUTH_ENABLED = _truthy(_env("WEB_AUTH_ENABLED", "1"))

# DEV OTP controls
WEB_AUTH_DEV_OTP_ENABLED = _truthy(_env("WEB_AUTH_DEV_OTP_ENABLED", "0"))
WEB_AUTH_OTP_TTL_SECONDS = int(_env("WEB_AUTH_OTP_TTL_SECONDS", "600") or "600")
WEB_AUTH_MASTER_OTP = _env("WEB_AUTH_MASTER_OTP", "")
WEB_AUTH_DEV_SHARED_SECRET = _env("WEB_AUTH_DEV_SHARED_SECRET", "")
WEB_AUTH_DEV_ALLOWED_CONTACTS_LIST = [
    x.strip()
    for x in (_env("WEB_AUTH_DEV_ALLOWED_CONTACTS_LIST", "")).split(",")
    if x.strip()
]

# Token lifetime (web_tokens.expires_at)
WEB_AUTH_TOKEN_TTL_DAYS = int(_env("WEB_AUTH_TOKEN_TTL_DAYS", "30") or "30")

# Hash pepper
HASH_PEPPER = _env("OTP_HASH_PEPPER", _env("ADMIN_API_KEY", "dev-pepper"))

# Cookie name
WEB_AUTH_COOKIE_NAME = _env("WEB_AUTH_COOKIE_NAME", _env("WEB_COOKIE_NAME", "ntg_session"))

# Tables
WEB_OTPS_TABLE = _env("WEB_OTPS_TABLE", "web_otps")
WEB_TOKENS_TABLE = _env("WEB_TOKENS_TABLE", "web_tokens")
ACCOUNTS_TABLE = _env("ACCOUNTS_TABLE", "accounts")


def _sb():
    return supabase() if callable(supabase) else supabase


# --------------------------------------------------
# Hashing
# --------------------------------------------------
def _hmac_sha256(value: str) -> str:
    pepper = (HASH_PEPPER or "dev-pepper").encode()
    return hmac.new(pepper, value.encode(), hashlib.sha256).hexdigest()


def _hash_otp(contact: str, purpose: str, otp: str) -> str:
    return _hmac_sha256(f"otp:{purpose}:{contact}:{otp}")


def _hash_token(raw_token: str) -> str:
    return _hmac_sha256(f"token:{raw_token}")


# --------------------------------------------------
# Bearer normalize
# --------------------------------------------------
def _normalize_bearer(auth_header: str) -> str:
    if not auth_header:
        return ""
    v = auth_header.strip()
    if v.lower().startswith("bearer "):
        return v[7:].strip()
    return ""


# --------------------------------------------------
# DEV guard
# --------------------------------------------------
def _dev_guard(contact: str, shared_secret: Optional[str]) -> Optional[str]:
    if not WEB_AUTH_ENABLED:
        return "Web auth is disabled"

    if not WEB_AUTH_DEV_OTP_ENABLED:
        return "DEV OTP is disabled"

    if WEB_AUTH_DEV_ALLOWED_CONTACTS_LIST and contact not in WEB_AUTH_DEV_ALLOWED_CONTACTS_LIST:
        return "Contact is not allowed in DEV mode"

    if WEB_AUTH_DEV_SHARED_SECRET:
        if not shared_secret or shared_secret != WEB_AUTH_DEV_SHARED_SECRET:
            return "Invalid shared_secret"

    return None


# --------------------------------------------------
# Account binding (provider=web, provider_user_id=contact)
#
# IMPORTANT:
# - web_tokens.account_id FK now points to accounts.id
# - therefore we must use accounts.id as the session account id
# --------------------------------------------------
def _extract_account_pk(row: Dict[str, Any]) -> Optional[str]:
    """
    Return the canonical account identifier that web_tokens.account_id should store.
    With FK(account_id) -> accounts.id, this MUST be accounts.id.
    """
    v = row.get("id")
    if v:
        return str(v)
    return None


def _get_or_create_web_account(contact: str) -> Tuple[bool, Optional[str], Optional[str]]:
    # Try fetch existing
    q = (
        _sb()
        .table(ACCOUNTS_TABLE)
        .select("id, account_id")
        .eq("provider", "web")
        .eq("provider_user_id", contact)
        .limit(1)
        .execute()
    )

    if getattr(q, "data", None):
        row = q.data[0]
        account_pk = _extract_account_pk(row)
        if not account_pk:
            return False, None, "Account exists but missing primary key (id)"
        # Optional: keep account_id alias in sync if blank
        try:
            if not row.get("account_id"):
                _sb().table(ACCOUNTS_TABLE).update({"account_id": account_pk}).eq("id", account_pk).execute()
        except Exception:
            pass
        return True, account_pk, None

    # Create new: set account_id to match id for compatibility (if your app still reads account_id)
    # Note: Postgres will generate 'id' automatically if default exists; Supabase returns it if selected.
    ins = (
        _sb()
        .table(ACCOUNTS_TABLE)
        .insert(
            {
                "provider": "web",
                "provider_user_id": contact,
                "display_name": contact,
                # keep compatibility: some schemas reuse phone_e164 for email
                "phone_e164": contact,
            }
        )
        .select("id")
        .execute()
    )

    if not getattr(ins, "data", None):
        return False, None, "Failed to create account"

    account_pk = str(ins.data[0]["id"])

    # Best-effort: sync account_id alias to id (if column exists)
    try:
        _sb().table(ACCOUNTS_TABLE).update({"account_id": account_pk}).eq("id", account_pk).execute()
    except Exception:
        pass

    return True, account_pk, None


# --------------------------------------------------
# OTP REQUEST (web_otps)
# --------------------------------------------------
def request_web_otp(
    contact: str,
    purpose: str,
    device_id: Optional[str] = None,
    shared_secret: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    contact = (contact or "").strip()
    purpose = (purpose or "").strip() or "web_login"

    if not contact:
        return {"ok": False, "error": "missing_contact"}
    if not WEB_AUTH_ENABLED:
        return {"ok": False, "error": "web_auth_disabled"}

    if WEB_AUTH_DEV_OTP_ENABLED:
        err = _dev_guard(contact, shared_secret)
        if err:
            return {"ok": False, "error": err}

    now = _now_utc()

    # revoke old unused OTPs
    _sb().table(WEB_OTPS_TABLE).update({"revoked_at": _iso(now)}).eq("contact", contact).eq(
        "purpose", purpose
    ).is_("used_at", "null").is_("revoked_at", "null").execute()

    otp = f"{secrets.randbelow(1000000):06d}"
    expires_at = now + timedelta(seconds=int(WEB_AUTH_OTP_TTL_SECONDS))
    code_hash = _hash_otp(contact, purpose, otp)

    payload: Dict[str, Any] = {
        "contact": contact,
        "purpose": purpose,
        "code_hash": code_hash,
        "expires_at": _iso(expires_at),
        "used_at": None,
        "revoked_at": None,
    }
    if device_id:
        payload["device_id"] = device_id
    if ip:
        payload["ip"] = ip
    if user_agent:
        payload["user_agent"] = user_agent

    _sb().table(WEB_OTPS_TABLE).insert(payload).execute()

    out: Dict[str, Any] = {
        "ok": True,
        "ttl_minutes": int(int(WEB_AUTH_OTP_TTL_SECONDS) / 60),
    }
    if WEB_AUTH_DEV_OTP_ENABLED:
        out["dev_otp"] = otp

    return out


# --------------------------------------------------
# OTP VERIFY (web_otps -> web_tokens)
# --------------------------------------------------
def verify_web_otp(
    contact: str,
    purpose: str,
    otp: str,
    device_id: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    contact = (contact or "").strip()
    purpose = (purpose or "").strip() or "web_login"
    otp = (otp or "").strip()

    if not contact or not otp:
        return {"ok": False, "error": "missing_contact_or_otp"}

    now = _now_utc()

    # Master OTP bypass
    if WEB_AUTH_MASTER_OTP and otp == WEB_AUTH_MASTER_OTP:
        ok, account_id, err = _get_or_create_web_account(contact)
        if not ok:
            return {"ok": False, "error": err}
        tok = _create_web_token(account_id, ip=ip, user_agent=user_agent, device_id=device_id)
        return {
            "ok": True,
            "account_id": account_id,
            "auth_mode": "cookie+bearer",
            "token": tok["token"],
            "expires_at": tok["expires_at"],
        }

    code_hash = _hash_otp(contact, purpose, otp)

    q = (
        _sb()
        .table(WEB_OTPS_TABLE)
        .select("*")
        .eq("contact", contact)
        .eq("purpose", purpose)
        .eq("code_hash", code_hash)
        .is_("used_at", "null")
        .is_("revoked_at", "null")
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if not getattr(q, "data", None):
        return {"ok": False, "error": "invalid_or_expired_otp"}

    row = q.data[0]
    exp = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
    if now > exp:
        _sb().table(WEB_OTPS_TABLE).update({"revoked_at": _iso(now)}).eq("id", row["id"]).execute()
        return {"ok": False, "error": "otp_expired"}

    _sb().table(WEB_OTPS_TABLE).update({"used_at": _iso(now)}).eq("id", row["id"]).execute()

    ok, account_id, err = _get_or_create_web_account(contact)
    if not ok:
        return {"ok": False, "error": err}

    tok = _create_web_token(account_id, ip=ip, user_agent=user_agent, device_id=device_id)

    return {
        "ok": True,
        "account_id": account_id,
        "auth_mode": "cookie+bearer",
        "token": tok["token"],
        "expires_at": tok["expires_at"],
    }


# --------------------------------------------------
# TOKEN CREATE (web_tokens) -> revoked BOOLEAN
# account_id stored here MUST match accounts.id (FK)
# --------------------------------------------------
def _create_web_token(
    account_id: str,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    device_id: Optional[str] = None,
) -> Dict[str, Any]:
    raw_token = secrets.token_hex(32)  # 64 hex chars
    token_hash = _hash_token(raw_token)
    now = _now_utc()
    expires_at = now + timedelta(days=int(WEB_AUTH_TOKEN_TTL_DAYS))

    payload: Dict[str, Any] = {
        "account_id": account_id,     # ✅ accounts.id (FK target)
        "token_hash": token_hash,
        "expires_at": _iso(expires_at),
        "revoked": False,
        "last_seen_at": _iso(now),
    }
    if ip:
        payload["ip"] = ip
    if user_agent:
        payload["user_agent"] = user_agent
    if device_id:
        payload["device_id"] = device_id

    _sb().table(WEB_TOKENS_TABLE).insert(payload).execute()

    return {"token": raw_token, "expires_at": _iso(expires_at)}


# --------------------------------------------------
# TOKEN VALIDATION (bearer token) -> revoked BOOLEAN
# --------------------------------------------------
def require_web_session(auth_header: str) -> Dict[str, Any]:
    token = _normalize_bearer(auth_header)
    if not token:
        return {"ok": False, "error": "missing_token"}

    token_hash = _hash_token(token)
    now = _now_utc()

    q = (
        _sb()
        .table(WEB_TOKENS_TABLE)
        .select("*")
        .eq("token_hash", token_hash)
        .eq("revoked", False)
        .limit(1)
        .execute()
    )

    if not getattr(q, "data", None):
        return {"ok": False, "error": "invalid_token"}

    row = q.data[0]
    exp = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
    if now > exp:
        _sb().table(WEB_TOKENS_TABLE).update({"revoked": True}).eq("token_hash", token_hash).execute()
        return {"ok": False, "error": "session_expired"}

    _sb().table(WEB_TOKENS_TABLE).update({"last_seen_at": _iso(now)}).eq("token_hash", token_hash).execute()

    return {"ok": True, "account_id": str(row["account_id"])}


# --------------------------------------------------
# AUTH RESOLUTION (cookie OR bearer) — PREFER BEARER FIRST
# --------------------------------------------------
def get_account_id_from_request(flask_request) -> Tuple[Optional[str], str]:
    # 1) Bearer first
    auth = (flask_request.headers.get("Authorization") or "").strip()
    if auth:
        out = require_web_session(auth)
        if out.get("ok"):
            return str(out.get("account_id")), "bearer"

    # 2) Cookie fallback
    raw_cookie = (flask_request.cookies.get(WEB_AUTH_COOKIE_NAME) or "").strip()
    if raw_cookie:
        token_hash = _hash_token(raw_cookie)
        now = _now_utc()

        q = (
            _sb()
            .table(WEB_TOKENS_TABLE)
            .select("*")
            .eq("token_hash", token_hash)
            .eq("revoked", False)
            .limit(1)
            .execute()
        )

        if getattr(q, "data", None):
            row = q.data[0]
            try:
                exp = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
                if now <= exp:
                    _sb().table(WEB_TOKENS_TABLE).update({"last_seen_at": _iso(now)}).eq(
                        "token_hash", token_hash
                    ).execute()
                    return str(row["account_id"]), "cookie"
            except Exception:
                pass

    return None, "none"


# --------------------------------------------------
# LOGOUT -> revoked BOOLEAN
# --------------------------------------------------
def logout_web_session(auth_header: str) -> Dict[str, Any]:
    token = _normalize_bearer(auth_header)
    if not token:
        return {"ok": False, "error": "missing_token"}

    token_hash = _hash_token(token)
    _sb().table(WEB_TOKENS_TABLE).update({"revoked": True}).eq("token_hash", token_hash).execute()
    return {"ok": True}
