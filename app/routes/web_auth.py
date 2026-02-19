# app/routes/web_auth.py
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request

from ..core.config import ENV
from ..core.supabase_client import supabase

bp = Blueprint("web_auth", __name__)

# ============================================================
# CONFIG
# ============================================================

WEB_OTP_LEN = int((os.getenv("WEB_OTP_LEN", "6") or "6").strip())
WEB_OTP_TTL_MINUTES = int((os.getenv("WEB_OTP_TTL_MINUTES", "10") or "10").strip())

# If WEB_OTP_ENABLED=0 => OTP is always WEB_OTP_STUB_CODE (dev convenience)
WEB_OTP_ENABLED = (os.getenv("WEB_OTP_ENABLED", "0").strip() == "1")
WEB_OTP_STUB_CODE = (os.getenv("WEB_OTP_STUB_CODE", "123456") or "123456").strip()

# Hashing salt for OTP (keep secret in prod)
OTP_HASH_SALT = (os.getenv("OTP_HASH_SALT", "dev_otp_salt_change_me") or "dev_otp_salt_change_me").strip()

# Stateless session token secret (HMAC). MUST be set in prod.
WEB_SESSION_SECRET = (os.getenv("WEB_SESSION_SECRET", "") or "").strip()
WEB_SESSION_TTL_DAYS = int((os.getenv("WEB_SESSION_TTL_DAYS", "30") or "30").strip())

# Table names (per your screenshots)
ACCOUNTS_TABLE = "accounts"
ACCOUNT_OTPS_TABLE = "account_otps"


# ============================================================
# TIME + CLIENT HELPERS
# ============================================================

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
    """
    Supports both:
      - supabase() factory style
      - supabase direct client style
    """
    try:
        return supabase()
    except TypeError:
        return supabase

def _table(name: str):
    return _sb().table(name)

def _clean(v: Any) -> str:
    return (v or "").strip()

def _normalize_phone(contact: str) -> str:
    """
    Your DB screenshot shows phone values like: 2348012345678 (no '+').
    We normalize by removing spaces and leading '+'.
    """
    s = _clean(contact).replace(" ", "")
    if s.startswith("+"):
        s = s[1:]
    return s

def _gen_otp() -> str:
    if WEB_OTP_LEN <= 1:
        return str(random.randint(0, 9))
    low = 10 ** (WEB_OTP_LEN - 1)
    high = (10 ** WEB_OTP_LEN) - 1
    return str(random.randint(low, high))

def _otp_hash(acct_id: str, purpose: str, otp: str) -> str:
    """
    Hash ties OTP to acct_id + purpose + salt.
    Stored in account_otps.code_hash
    """
    msg = f"{acct_id}|{purpose}|{otp}|{OTP_HASH_SALT}".encode("utf-8")
    return hashlib.sha256(msg).hexdigest()


# ============================================================
# TOKEN (STATELESS HMAC)
# ============================================================

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def _token_sign(payload: Dict[str, Any]) -> str:
    """
    Creates an opaque token:
      base64url(json_payload) + "." + base64url(hmac_sha256(payload_bytes))

    NOTE:
    - This token is validated ONLY by this file (/web/auth/me).
    - If you want other protected endpoints (require_auth_plus) to accept it,
      you must align require_auth_plus validation with this token format.
    """
    if (ENV or "").lower() == "prod" and not WEB_SESSION_SECRET:
        # Fail closed in prod if secret not set
        raise RuntimeError("WEB_SESSION_SECRET not set")

    secret = (WEB_SESSION_SECRET or "dev_web_session_secret_change_me").encode("utf-8")
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = _b64url_encode(payload_bytes)
    sig = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(sig)}"

def _token_verify(token: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    try:
        token = _clean(token)
        if not token or "." not in token:
            return False, None, "invalid_token"

        body_b64, sig_b64 = token.split(".", 1)
        payload_bytes = _b64url_decode(body_b64)
        got_sig = _b64url_decode(sig_b64)

        secret = (WEB_SESSION_SECRET or "dev_web_session_secret_change_me").encode("utf-8")
        want_sig = hmac.new(secret, payload_bytes, hashlib.sha256).digest()

        if not hmac.compare_digest(got_sig, want_sig):
            return False, None, "bad_signature"

        payload = json.loads(payload_bytes.decode("utf-8"))

        exp = int(payload.get("exp") or 0)
        now = int(time.time())
        if exp <= now:
            return False, None, "token_expired"

        return True, payload, "ok"
    except Exception:
        return False, None, "invalid_token"


# ============================================================
# ACCOUNT LOOKUP / CREATE (accounts table)
# ============================================================

def _find_account_by_phone(phone_norm: str) -> Optional[Dict[str, Any]]:
    """
    Tries accounts.phone_e164, accounts.phone, accounts.provider_user_id.
    Your screenshot shows provider='web', provider_user_id=phone, phone_e164=phone.
    """
    try:
        res = (
            _table(ACCOUNTS_TABLE)
            .select("id, provider, provider_user_id, phone_e164, phone")
            .or_(
                ",".join(
                    [
                        f"phone_e164.eq.{phone_norm}",
                        f"phone.eq.{phone_norm}",
                        f"provider_user_id.eq.{phone_norm}",
                    ]
                )
            )
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None

def _create_web_account(phone_norm: str) -> Optional[Dict[str, Any]]:
    """
    Creates an account row for web provider.
    Keeps insert minimal to match your columns.
    """
    payload = {
        "provider": "web",
        "provider_user_id": phone_norm,
        "phone_e164": phone_norm,
        "phone": phone_norm,
        # display_name can remain NULL
        # has_used_trial default/NULL is ok; your screenshot shows FALSE
    }
    try:
        res = _table(ACCOUNTS_TABLE).insert(payload).execute()
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None


# ============================================================
# OTP STORAGE (account_otps table)
# Columns (per your screenshot):
#  - otp_id (pk)
#  - acct_id (uuid)
#  - purpose (text)
#  - channel (text)
#  - code_hash (text)
#  - expires_at (timestamptz)
#  - verified (bool)
#  - created_at (timestamptz)
# ============================================================

def _insert_account_otp(acct_id: str, purpose: str, channel: str, code_hash: str, expires_at: datetime) -> None:
    payload = {
        "acct_id": acct_id,
        "purpose": purpose,
        "channel": channel,
        "code_hash": code_hash,
        "expires_at": _iso(expires_at),
        "verified": False,
        "created_at": _iso(_now_utc()),
    }
    try:
        _table(ACCOUNT_OTPS_TABLE).insert(payload).execute()
    except Exception:
        # Best-effort; route will still work in DEV mode or fail gracefully in verify
        return

def _get_latest_unverified_otp(acct_id: str, purpose: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            _table(ACCOUNT_OTPS_TABLE)
            .select("otp_id, acct_id, purpose, channel, code_hash, expires_at, verified, created_at")
            .eq("acct_id", acct_id)
            .eq("purpose", purpose)
            .eq("verified", False)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None

def _mark_otp_verified(otp_id: Any) -> None:
    try:
        _table(ACCOUNT_OTPS_TABLE).update({"verified": True}).eq("otp_id", otp_id).execute()
    except Exception:
        return


# ============================================================
# ROUTES
# ============================================================

@bp.post("/web/auth/request-otp")
def web_request_otp():
    data = request.get_json(silent=True) or {}
    contact = _clean(data.get("contact"))
    purpose = _clean(data.get("purpose")) or "web_login"
    channel = _clean(data.get("channel")) or "sms"

    if not contact:
        return jsonify({"ok": False, "error": "missing_contact"}), 400

    phone_norm = _normalize_phone(contact)

    acct = _find_account_by_phone(phone_norm)
    if not acct:
        acct = _create_web_account(phone_norm)

    if not acct or not acct.get("id"):
        return jsonify({"ok": False, "error": "account_create_failed"}), 500

    acct_id = str(acct["id"])

    # OTP
    otp = WEB_OTP_STUB_CODE if not WEB_OTP_ENABLED else _gen_otp()

    expires_at = _now_utc() + timedelta(minutes=max(1, WEB_OTP_TTL_MINUTES))
    code_hash = _otp_hash(acct_id=acct_id, purpose=purpose, otp=otp)

    _insert_account_otp(
        acct_id=acct_id,
        purpose=purpose,
        channel=channel,
        code_hash=code_hash,
        expires_at=expires_at,
    )

    # Only expose dev OTP outside prod
    if (ENV or "").lower() != "prod":
        return jsonify(
            {
                "ok": True,
                "contact": contact,
                "phone": phone_norm,
                "purpose": purpose,
                "channel": channel,
                "acct_id": acct_id,
                "dev_otp": otp,
                "ttl_minutes": WEB_OTP_TTL_MINUTES,
                "mode": "stub" if not WEB_OTP_ENABLED else "real",
            }
        )

    return jsonify(
        {
            "ok": True,
            "contact": contact,
            "phone": phone_norm,
            "purpose": purpose,
            "channel": channel,
            "acct_id": acct_id,
            "ttl_minutes": WEB_OTP_TTL_MINUTES,
        }
    )


@bp.post("/web/auth/verify-otp")
def web_verify_otp():
    data = request.get_json(silent=True) or {}
    contact = _clean(data.get("contact"))
    otp = _clean(data.get("otp"))
    purpose = _clean(data.get("purpose")) or "web_login"

    if not contact or not otp:
        return jsonify({"ok": False, "error": "missing_contact_or_otp"}), 400

    phone_norm = _normalize_phone(contact)

    acct = _find_account_by_phone(phone_norm)
    if not acct or not acct.get("id"):
        return jsonify({"ok": False, "error": "account_not_found"}), 404

    acct_id = str(acct["id"])

    rec = _get_latest_unverified_otp(acct_id=acct_id, purpose=purpose)
    if not rec:
        return jsonify({"ok": False, "error": "otp_not_found"}), 401

    expires_at = _parse_iso(rec.get("expires_at"))
    if not expires_at:
        return jsonify({"ok": False, "error": "otp_record_invalid"}), 401

    if _now_utc() > expires_at:
        return jsonify({"ok": False, "error": "otp_expired"}), 401

    expected = _clean(rec.get("code_hash"))
    if not expected:
        return jsonify({"ok": False, "error": "otp_record_invalid"}), 401

    got = _otp_hash(acct_id=acct_id, purpose=purpose, otp=otp)
    if not hmac.compare_digest(expected, got):
        return jsonify({"ok": False, "error": "invalid_otp"}), 401

    _mark_otp_verified(rec.get("otp_id"))

    # Issue stateless session token
    now = int(time.time())
    exp = now + int(max(1, WEB_SESSION_TTL_DAYS)) * 24 * 60 * 60
    token = _token_sign({"acct_id": acct_id, "phone": phone_norm, "iat": now, "exp": exp, "purpose": purpose})

    return jsonify(
        {
            "ok": True,
            "token": token,
            "account_id": acct_id,
            "phone": phone_norm,
            "expires_in": exp - now,
        }
    )


@bp.get("/web/auth/me")
def web_me():
    auth = _clean(request.headers.get("Authorization"))
    token = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    if not token:
        return jsonify({"ok": False, "error": "missing_token"}), 401

    ok, payload, reason = _token_verify(token)
    if not ok or not payload:
        return jsonify({"ok": False, "error": reason}), 401

    acct_id = _clean(payload.get("acct_id"))
    if not acct_id:
        return jsonify({"ok": False, "error": "invalid_token"}), 401

    # Optional: confirm account still exists
    try:
        res = (
            _table(ACCOUNTS_TABLE)
            .select("id")
            .eq("id", acct_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return jsonify({"ok": False, "error": "account_not_found"}), 401
    except Exception:
        # If DB is temporarily unavailable, still allow token-based /me
        pass

    return jsonify({"ok": True, "account_id": acct_id})
