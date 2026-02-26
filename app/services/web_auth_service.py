# app/services/web_auth_service.py
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Request

# ✅ Do NOT hard-import missing symbols from app.core.config
# We import the module, then use getattr(...) with fallbacks.
try:
    import app.core.config as _cfg  # type: ignore
except Exception:  # pragma: no cover
    _cfg = None  # type: ignore

from app.core.supabase_client import supabase


# -----------------------------
# Safe config getters
# -----------------------------
def _cfg_get(name: str, default: Any = None) -> Any:
    if _cfg is None:
        return default
    return getattr(_cfg, name, default)


def _truthy(v: Any) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


# ---- Config values (safe) ----
WEB_AUTH_ENABLED = _truthy(_cfg_get("WEB_AUTH_ENABLED", os.getenv("WEB_AUTH_ENABLED", "0")))
WEB_AUTH_DEV_OTP_ENABLED = _truthy(_cfg_get("WEB_AUTH_DEV_OTP_ENABLED", os.getenv("WEB_AUTH_DEV_OTP_ENABLED", "0")))

WEB_AUTH_OTP_TTL_SECONDS = int(_cfg_get("WEB_AUTH_OTP_TTL_SECONDS", os.getenv("WEB_AUTH_OTP_TTL_SECONDS", "600")) or 600)

WEB_AUTH_MASTER_OTP = str(_cfg_get("WEB_AUTH_MASTER_OTP", os.getenv("WEB_AUTH_MASTER_OTP", "")) or "").strip()

WEB_AUTH_DEV_SHARED_SECRET = str(_cfg_get("WEB_AUTH_DEV_SHARED_SECRET", os.getenv("WEB_AUTH_DEV_SHARED_SECRET", "")) or "").strip()

# allowed phones list: config may define list already; env may define comma list
_allowed_list = _cfg_get("WEB_AUTH_DEV_ALLOWED_PHONES_LIST", None)
if isinstance(_allowed_list, list):
    WEB_AUTH_DEV_ALLOWED_PHONES_LIST = [str(x).strip() for x in _allowed_list if str(x).strip()]
else:
    _raw = str(os.getenv("WEB_AUTH_DEV_ALLOWED_PHONES_LIST", "") or "").strip()
    WEB_AUTH_DEV_ALLOWED_PHONES_LIST = [x.strip() for x in _raw.split(",") if x.strip()]

OTP_HASH_PEPPER = str(_cfg_get("OTP_HASH_PEPPER", os.getenv("OTP_HASH_PEPPER", "")) or "").strip()


# --------------------------------------------------
# Time helpers
# --------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------
# Hashing
# --------------------------------------------------
def _hash(value: str) -> str:
    pepper = (OTP_HASH_PEPPER or os.getenv("ADMIN_API_KEY") or "dev-pepper").encode()
    return hmac.new(pepper, value.encode(), hashlib.sha256).hexdigest()


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
# Token extraction (bearer / X-Auth-Token / cookie)
# --------------------------------------------------
def _extract_web_token_from_request(req: Request) -> str:
    bearer = _normalize_bearer(req.headers.get("Authorization") or "")
    if bearer:
        return bearer

    x_token = (req.headers.get("X-Auth-Token") or "").strip()
    if x_token:
        return x_token

    cookie_name = (os.getenv("WEB_AUTH_COOKIE_NAME") or "ntg_session").strip() or "ntg_session"
    c = (req.cookies.get(cookie_name) or "").strip()
    if c:
        return c

    return ""


# --------------------------------------------------
# DEV guard
# --------------------------------------------------
def _dev_guard(phone_e164: str, shared_secret: Optional[str]) -> Optional[str]:
    if not WEB_AUTH_ENABLED:
        return "Web auth is disabled"

    if not WEB_AUTH_DEV_OTP_ENABLED:
        return "DEV OTP is disabled"

    if WEB_AUTH_DEV_ALLOWED_PHONES_LIST and phone_e164 not in WEB_AUTH_DEV_ALLOWED_PHONES_LIST:
        return "Phone is not allowed in DEV mode"

    if WEB_AUTH_DEV_SHARED_SECRET:
        if not shared_secret or shared_secret != WEB_AUTH_DEV_SHARED_SECRET:
            return "Invalid shared_secret"

    return None


# --------------------------------------------------
# Account binding
# --------------------------------------------------
def _get_or_create_account_by_phone(phone_e164: str) -> Tuple[bool, Optional[str], Optional[str]]:
    q = (
        supabase.table("accounts")
        .select("id")
        .eq("phone_e164", phone_e164)
        .limit(1)
        .execute()
    )

    if q.data:
        account_id = q.data[0]["id"]
    else:
        ins = (
            supabase.table("accounts")
            .insert({"phone_e164": phone_e164})
            .select("id")
            .execute()
        )
        if not ins.data:
            return False, None, "Failed to create account"
        account_id = ins.data[0]["id"]

    return True, account_id, None


# --------------------------------------------------
# OTP REQUEST
# --------------------------------------------------
def request_web_otp(phone_e164: str, device_id: Optional[str], shared_secret: Optional[str]):
    err = _dev_guard(phone_e164, shared_secret)
    if err:
        return {"ok": False, "error": err}

    # soft revoke old OTPs
    supabase.table("web_otps").update({"revoked": True}).eq("phone_e164", phone_e164).eq("revoked", False).execute()

    otp = f"{secrets.randbelow(1000000):06d}"
    expires_at = _now_utc() + timedelta(seconds=int(WEB_AUTH_OTP_TTL_SECONDS))

    otp_hash = _hash(f"{phone_e164}:{otp}")

    supabase.table("web_otps").insert(
        {
            "phone_e164": phone_e164,
            "device_id": device_id,
            "otp_hash": otp_hash,
            "expires_at": _iso(expires_at),
            "attempts": 0,
            "revoked": False,
        }
    ).execute()

    return {"ok": True, "dev": True, "otp": otp, "expires_at": _iso(expires_at)}


# --------------------------------------------------
# OTP VERIFY
# --------------------------------------------------
def verify_web_otp(phone_e164: str, otp: str, device_id: Optional[str]):
    if not phone_e164 or not otp:
        return {"ok": False, "error": "Missing phone_e164 or otp"}

    if WEB_AUTH_MASTER_OTP and otp == WEB_AUTH_MASTER_OTP:
        ok, account_id, error = _get_or_create_account_by_phone(phone_e164)
        if not ok:
            return {"ok": False, "error": error}
        return _create_session(account_id, phone_e164, device_id)

    q = (
        supabase.table("web_otps")
        .select("*")
        .eq("phone_e164", phone_e164)
        .eq("revoked", False)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if not q.data:
        return {"ok": False, "error": "OTP not found"}

    row = q.data[0]
    incoming_hash = _hash(f"{phone_e164}:{otp}")
    if incoming_hash != row["otp_hash"]:
        return {"ok": False, "error": "Invalid OTP"}

    supabase.table("web_otps").update({"revoked": True}).eq("id", row["id"]).execute()

    ok, account_id, error = _get_or_create_account_by_phone(phone_e164)
    if not ok:
        return {"ok": False, "error": error}

    return _create_session(account_id, phone_e164, device_id)


# --------------------------------------------------
# SESSION CREATE
# --------------------------------------------------
def _create_session(account_id: str, phone_e164: str, device_id: Optional[str]):
    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash(f"session:{raw_token}")

    expires_at = _now_utc() + timedelta(days=30)

    supabase.table("web_sessions").insert(
        {
            "account_id": account_id,
            "phone_e164": phone_e164,
            "device_id": device_id,
            "token_hash": token_hash,
            "expires_at": _iso(expires_at),
            "revoked": False,
        }
    ).execute()

    return {"ok": True, "account_id": account_id, "token": raw_token, "expires_at": _iso(expires_at)}


# --------------------------------------------------
# SESSION VALIDATION (header-based, existing)
# --------------------------------------------------
def require_web_session(auth_header: str):
    token = _normalize_bearer(auth_header)
    if not token:
        return {"ok": False, "error": "missing_token"}

    token_hash = _hash(f"session:{token}")

    q = supabase.table("web_sessions").select("*").eq("token_hash", token_hash).eq("revoked", False).limit(1).execute()
    if not q.data:
        return {"ok": False, "error": "invalid_token"}

    row = q.data[0]
    exp = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if _now_utc() > exp:
        return {"ok": False, "error": "session_expired"}

    return {"ok": True, "account_id": row["account_id"]}


# --------------------------------------------------
# SESSION VALIDATION (request-based, NEW helper)
# --------------------------------------------------
def resolve_web_identity_from_request(req: Request) -> Dict[str, Any]:
    token = _extract_web_token_from_request(req)
    if not token:
        return {"ok": False, "error": "missing_token"}

    token_hash = _hash(f"session:{token}")

    q = supabase.table("web_sessions").select("*").eq("token_hash", token_hash).eq("revoked", False).limit(1).execute()
    if not q.data:
        return {"ok": False, "error": "invalid_token"}

    row = q.data[0]
    exp = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if _now_utc() > exp:
        return {"ok": False, "error": "session_expired"}

    phone = (row.get("phone_e164") or "").strip() or None
    cookie_name = (os.getenv("WEB_AUTH_COOKIE_NAME") or "ntg_session").strip() or "ntg_session"
    source = "cookie" if (req.cookies.get(cookie_name) or "").strip() else "bearer"

    return {"ok": True, "account_id": row["account_id"], "provider_user_id": phone, "source": source}


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------
def logout_web_session(auth_header: str):
    token = _normalize_bearer(auth_header)
    if not token:
        return {"ok": False, "error": "missing_token"}

    token_hash = _hash(f"session:{token}")
    supabase.table("web_sessions").update({"revoked": True}).eq("token_hash", token_hash).execute()
    return {"ok": True}
