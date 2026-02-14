# app/services/web_auth_service.py
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from app.core.config import (
    WEB_AUTH_ENABLED,
    WEB_AUTH_DEV_OTP_ENABLED,
    WEB_AUTH_OTP_TTL_SECONDS,
    WEB_AUTH_MASTER_OTP,
    WEB_AUTH_DEV_SHARED_SECRET,
    WEB_AUTH_DEV_ALLOWED_PHONES_LIST,
    OTP_HASH_PEPPER,
)
from app.core.supabase_client import supabase


# -----------------------------
# Helpers
# -----------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash(value: str) -> str:
    """
    HMAC-SHA256 hash using OTP_HASH_PEPPER (recommended) or fallback to env SECRET-ish.
    """
    pepper = (OTP_HASH_PEPPER or os.getenv("ADMIN_API_KEY") or "dev-pepper").encode("utf-8")
    msg = value.encode("utf-8")
    return hmac.new(pepper, msg, hashlib.sha256).hexdigest()


def _normalize_bearer(auth_header: str) -> str:
    if not auth_header:
        return ""
    v = auth_header.strip()
    if v.lower().startswith("bearer "):
        return v[7:].strip()
    return ""


def _dev_guard(phone_e164: str, shared_secret: Optional[str]) -> Optional[str]:
    """
    Returns error string if blocked, else None.
    """
    if not WEB_AUTH_ENABLED:
        return "Web auth is disabled"

    # If dev mode is OFF, you’ll later plug SMS/Email providers.
    if not WEB_AUTH_DEV_OTP_ENABLED:
        return "DEV OTP is disabled"

    if WEB_AUTH_DEV_ALLOWED_PHONES_LIST and phone_e164 not in WEB_AUTH_DEV_ALLOWED_PHONES_LIST:
        return "Phone is not allowed in DEV mode"

    if WEB_AUTH_DEV_SHARED_SECRET:
        if not shared_secret or shared_secret != WEB_AUTH_DEV_SHARED_SECRET:
            return "Invalid shared_secret"

    return None


def _get_or_create_account_by_phone(phone_e164: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Returns: (ok, account_id, error)
    Uses accounts.phone_e164 as the primary web identity binding.
    Also ensures a row exists in account_identities for provider='web'
    """
    # 1) Try find account by phone_e164
    q = (
        supabase.table("accounts")
        .select("id, phone_e164")
        .eq("phone_e164", phone_e164)
        .limit(1)
        .execute()
    )
    if q.data and len(q.data) > 0:
        account_id = q.data[0]["id"]
    else:
        # Create account
        ins = (
            supabase.table("accounts")
            .insert({"phone_e164": phone_e164})
            .select("id")
            .execute()
        )
        if not ins.data:
            return False, None, "Failed to create account"
        account_id = ins.data[0]["id"]

    # 2) Ensure account_identities (provider='web') exists
    # provider_user_id for web = phone_e164
    existing = (
        supabase.table("account_identities")
        .select("id")
        .eq("account_id", account_id)
        .eq("provider", "web")
        .eq("provider_user_id", phone_e164)
        .limit(1)
        .execute()
    )
    if not existing.data:
        supabase.table("account_identities").insert(
            {
                "account_id": account_id,
                "provider": "web",
                "provider_user_id": phone_e164,
            }
        ).execute()

    return True, account_id, None


# -----------------------------
# OTP flow
# -----------------------------
def request_web_otp(phone_e164: str, device_id: Optional[str], shared_secret: Optional[str]) -> Dict[str, Any]:
    err = _dev_guard(phone_e164=phone_e164, shared_secret=shared_secret)
    if err:
        return {"ok": False, "error": err}

    # generate otp
    # If master OTP is set, allow it for internal testing (still store normal OTP too)
    otp = f"{secrets.randbelow(1000000):06d}"

    expires_at = _now_utc() + timedelta(seconds=int(WEB_AUTH_OTP_TTL_SECONDS))
    otp_hash = _hash(f"{phone_e164}:{otp}")

    # soft-revoke previous active OTPs for same phone
    supabase.table("web_otps").update({"revoked": True}).eq("phone_e164", phone_e164).eq("revoked", False).execute()

    # insert new otp record
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

    # DEV convenience: return OTP so you don't pay any provider yet.
    return {
        "ok": True,
        "dev": True,
        "phone_e164": phone_e164,
        "expires_at": _iso(expires_at),
        "otp": otp,  # IMPORTANT: only because DEV OTP is enabled
        "note": "DEV OTP enabled: otp returned in response. Disable in production.",
    }


def verify_web_otp(phone_e164: str, otp: str, device_id: Optional[str]) -> Dict[str, Any]:
    if not WEB_AUTH_ENABLED:
        return {"ok": False, "error": "Web auth is disabled"}

    if not phone_e164 or not otp:
        return {"ok": False, "error": "Missing phone_e164 or otp"}

    # Allow MASTER OTP if configured (internal use)
    if WEB_AUTH_MASTER_OTP and otp == WEB_AUTH_MASTER_OTP:
        ok, account_id, error = _get_or_create_account_by_phone(phone_e164)
        if not ok:
            return {"ok": False, "error": error}
        return _create_session(account_id=account_id, phone_e164=phone_e164, device_id=device_id)

    # Find latest unrevoked OTP row
    q = (
        supabase.table("web_otps")
        .select("id, otp_hash, expires_at, attempts, revoked, device_id")
        .eq("phone_e164", phone_e164)
        .eq("revoked", False)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if not q.data:
        return {"ok": False, "error": "OTP not found or already used"}

    row = q.data[0]
    otp_id = row["id"]
    expires_at = row["expires_at"]
    attempts = int(row.get("attempts") or 0)

    # basic device check (optional)
    if row.get("device_id") and device_id and row["device_id"] != device_id:
        return {"ok": False, "error": "Device mismatch"}

    # expiry check
    try:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except Exception:
        exp_dt = _now_utc() - timedelta(days=1)

    if _now_utc() > exp_dt:
        supabase.table("web_otps").update({"revoked": True}).eq("id", otp_id).execute()
        return {"ok": False, "error": "OTP expired"}

    # attempt limit
    if attempts >= 5:
        supabase.table("web_otps").update({"revoked": True}).eq("id", otp_id).execute()
        return {"ok": False, "error": "Too many attempts"}

    # verify
    incoming_hash = _hash(f"{phone_e164}:{otp}")
    if incoming_hash != row["otp_hash"]:
        supabase.table("web_otps").update({"attempts": attempts + 1}).eq("id", otp_id).execute()
        return {"ok": False, "error": "Invalid OTP"}

    # mark otp used
    supabase.table("web_otps").update({"revoked": True}).eq("id", otp_id).execute()

    ok, account_id, error = _get_or_create_account_by_phone(phone_e164)
    if not ok:
        return {"ok": False, "error": error}

    return _create_session(account_id=account_id, phone_e164=phone_e164, device_id=device_id)


def _create_session(account_id: str, phone_e164: str, device_id: Optional[str]) -> Dict[str, Any]:
    # 30 days session for web (adjust later)
    expires_at = _now_utc() + timedelta(days=30)

    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash(f"session:{raw_token}")

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

    return {
        "ok": True,
        "account_id": account_id,
        "session_token": raw_token,  # store in browser; never store raw in DB
        "expires_at": _iso(expires_at),
    }


# -----------------------------
# Session enforcement
# -----------------------------
def require_web_session(auth_header: str) -> Dict[str, Any]:
    if not WEB_AUTH_ENABLED:
        return {"ok": False, "error": "Web auth is disabled"}

    token = _normalize_bearer(auth_header)
    if not token:
        return {"ok": False, "error": "Missing bearer token"}

    token_hash = _hash(f"session:{token}")

    q = (
        supabase.table("web_sessions")
        .select("id, account_id, phone_e164, expires_at, revoked")
        .eq("token_hash", token_hash)
        .eq("revoked", False)
        .limit(1)
        .execute()
    )
    if not q.data:
        return {"ok": False, "error": "Invalid session"}

    row = q.data[0]
    try:
        exp_dt = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    except Exception:
        exp_dt = _now_utc() - timedelta(days=1)

    if _now_utc() > exp_dt:
        supabase.table("web_sessions").update({"revoked": True}).eq("id", row["id"]).execute()
        return {"ok": False, "error": "Session expired"}

    return {
        "ok": True,
        "account_id": row["account_id"],
        "phone_e164": row.get("phone_e164"),
        "expires_at": row["expires_at"],
    }


def logout_web_session(auth_header: str) -> Dict[str, Any]:
    token = _normalize_bearer(auth_header)
    if not token:
        return {"ok": False, "error": "Missing bearer token"}

    token_hash = _hash(f"session:{token}")
    supabase.table("web_sessions").update({"revoked": True}).eq("token_hash", token_hash).execute()
    return {"ok": True}
