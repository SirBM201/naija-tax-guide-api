# app/routes/web_auth.py
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request, g

from app.core.supabase_client import supabase
from app.core.auth import require_auth_plus  # validates sessions in web_tokens
from app.core.config import (
    WEB_AUTH_ENABLED,
    WEB_TOKEN_TABLE,
    WEB_TOKEN_PEPPER,
)

bp = Blueprint("web_auth", __name__)

# -----------------------------
# Helpers
# -----------------------------
def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "y", "on")


ENV = _env("ENV", "prod").lower()
WEB_AUTH_DEBUG = _truthy(_env("WEB_AUTH_DEBUG", "0"))

WEB_OTP_TABLE = _env("WEB_OTP_TABLE", "web_otps")
WEB_OTP_PEPPER = _env("WEB_OTP_PEPPER", WEB_TOKEN_PEPPER)
WEB_SESSION_TTL_DAYS = int(_env("WEB_SESSION_TTL_DAYS", "30") or "30")
WEB_OTP_TTL_MINUTES = int(_env("WEB_OTP_TTL_MINUTES", "10") or "10")

# Optional: whether to return OTP in response (dev/testing)
WEB_DEV_RETURN_OTP = _truthy(_env("WEB_DEV_RETURN_OTP", "0")) or (ENV == "dev")

# --- Column mapping (match your Supabase schema) ---
# Your table shows: contact, purpose, code_hash, code_plain, phone_e164, otp_code, used, expires_at, created_at, used_at
OTP_COL_CONTACT = _env("WEB_OTP_COL_CONTACT", "contact")
OTP_COL_PURPOSE = _env("WEB_OTP_COL_PURPOSE", "purpose")
OTP_COL_CODE_HASH = _env("WEB_OTP_COL_CODE_HASH", "code_hash")
OTP_COL_CODE_PLAIN = _env("WEB_OTP_COL_CODE_PLAIN", "code_plain")
OTP_COL_PHONE_E164 = _env("WEB_OTP_COL_PHONE_E164", "phone_e164")
OTP_COL_OTP_CODE = _env("WEB_OTP_COL_OTP_CODE", "otp_code")
OTP_COL_EXPIRES_AT = _env("WEB_OTP_COL_EXPIRES_AT", "expires_at")
OTP_COL_USED = _env("WEB_OTP_COL_USED", "used")
OTP_COL_USED_AT = _env("WEB_OTP_COL_USED_AT", "used_at")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _otp_hash(contact: str, purpose: str, otp: str) -> str:
    # peppered hash; ties OTP to contact+purpose
    return _sha256_hex(f"{WEB_OTP_PEPPER}:{contact}:{purpose}:{otp}")


def _token_hash(raw_token: str) -> str:
    # MUST match app/core/auth.py
    return _sha256_hex(f"{WEB_TOKEN_PEPPER}:{raw_token}")


def _normalize_contact(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return ""
    if v.startswith("+"):
        return v
    if v.startswith("234"):
        return "+" + v
    if v.startswith("0"):
        return "+234" + v[1:]
    return v


def _extract_supabase_error(e: Exception) -> Dict[str, Any]:
    """
    Try to extract useful info from supabase-py / postgrest errors.
    Error shapes can vary by version.
    """
    info: Dict[str, Any] = {
        "type": e.__class__.__name__,
        "message": str(e),
    }

    # common fields seen in APIError/PostgrestError
    for k in ("code", "details", "hint", "status", "status_code"):
        if hasattr(e, k):
            try:
                info[k] = getattr(e, k)
            except Exception:
                pass

    # sometimes error payload is stored in .args[0]
    try:
        if getattr(e, "args", None):
            info["args"] = [str(a) for a in e.args[:3]]
    except Exception:
        pass

    # best-effort: some errors include a dict payload
    try:
        first = e.args[0] if getattr(e, "args", None) else None
        if isinstance(first, dict):
            info["payload"] = first
    except Exception:
        pass

    # some libs expose .json() or .to_dict()
    for meth in ("json", "to_dict", "dict"):
        if hasattr(e, meth):
            try:
                fn = getattr(e, meth)
                val = fn() if callable(fn) else fn
                if isinstance(val, dict):
                    info[meth] = val
            except Exception:
                pass

    return info


def _extract_response_error(res: Any) -> Optional[Dict[str, Any]]:
    """
    Some supabase/postgrest versions do NOT raise exceptions on 4xx/5xx,
    but instead return an object with `.error`.
    """
    try:
        err_obj = getattr(res, "error", None)
        if not err_obj:
            return None

        detail: Dict[str, Any] = {
            "type": err_obj.__class__.__name__,
            "message": getattr(err_obj, "message", None) or str(err_obj),
        }
        for k in ("code", "details", "hint", "status", "status_code"):
            if hasattr(err_obj, k):
                try:
                    detail[k] = getattr(err_obj, k)
                except Exception:
                    pass

        # Try to pull any dict-like payload
        try:
            if getattr(err_obj, "args", None):
                detail["args"] = [str(a) for a in err_obj.args[:3]]
        except Exception:
            pass

        return detail
    except Exception:
        return {"type": "UnknownError", "message": "Failed to extract response error"}


def _upsert_account_for_contact(contact: str) -> Optional[str]:
    """
    Ensure an account exists for this contact and return account_id.
    accounts table must exist.
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
        rows = (res.data or []) if hasattr(res, "data") else []
        if rows:
            return rows[0].get("account_id")

        account_id = secrets.token_hex(16)
        _sb().table("accounts").insert(
            {
                "account_id": account_id,
                "provider": "web",
                "provider_user_id": contact,
                "display_name": contact,
                "phone": contact,
            }
        ).execute()
        return account_id
    except Exception:
        return None


# -----------------------------
# Routes
# -----------------------------
@bp.post("/request-otp")
@bp.post("/web/auth/request-otp")
def request_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled"}), 403

    data: Dict[str, Any] = request.get_json(silent=True) or {}
    contact = _normalize_contact(str(data.get("contact") or ""))
    purpose = (data.get("purpose") or "web_login").strip() or "web_login"

    if not contact:
        return jsonify({"ok": False, "error": "missing_contact"}), 400

    # Create OTP
    otp = "123456" if ENV == "dev" else f"{secrets.randbelow(1000000):06d}"
    expires_at = _now_utc() + timedelta(minutes=WEB_OTP_TTL_MINUTES)
    code_hash = _otp_hash(contact, purpose, otp)

    # Store OTP in DB (MATCH YOUR TABLE SCHEMA)
    payload: Dict[str, Any] = {
        OTP_COL_CONTACT: contact,
        OTP_COL_PURPOSE: purpose,
        OTP_COL_CODE_HASH: code_hash,
        OTP_COL_CODE_PLAIN: otp if WEB_DEV_RETURN_OTP else None,  # optional
        OTP_COL_PHONE_E164: contact,  # your schema has phone_e164
        OTP_COL_OTP_CODE: otp if WEB_DEV_RETURN_OTP else None,  # your schema has otp_code
        OTP_COL_EXPIRES_AT: expires_at.isoformat().replace("+00:00", "Z"),
        OTP_COL_USED: False,
    }

    # Remove None fields so Supabase doesn't reject type constraints
    payload = {k: v for k, v in payload.items() if v is not None}

    # Insert + capture supabase error details (both raise + return styles)
    try:
        res = _sb().table(WEB_OTP_TABLE).insert(payload).execute()

        # Some versions return an error object instead of raising
        resp_err = _extract_response_error(res)
        if resp_err:
            print(f"[web_auth] request_otp insert returned error: {resp_err}")
            if ENV == "dev" or WEB_AUTH_DEBUG:
                return (
                    jsonify(
                        {
                            "ok": False,
                            "error": "otp_store_failed",
                            "supabase": resp_err,
                            "payload_keys": list(payload.keys()),
                        }
                    ),
                    500,
                )
            return jsonify({"ok": False, "error": "otp_store_failed"}), 500

    except Exception as e:
        err = _extract_supabase_error(e)
        print(f"[web_auth] request_otp insert failed: {err}")
        if ENV == "dev" or WEB_AUTH_DEBUG:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "otp_store_failed",
                        "supabase": err,
                        "payload_keys": list(payload.keys()),
                    }
                ),
                500,
            )
        return jsonify({"ok": False, "error": "otp_store_failed"}), 500

    resp = {"ok": True, "contact": contact, "purpose": purpose}
    if WEB_DEV_RETURN_OTP:
        resp["dev_otp"] = otp
    return jsonify(resp)


@bp.post("/verify-otp")
@bp.post("/web/auth/verify-otp")
def verify_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled"}), 403

    data: Dict[str, Any] = request.get_json(silent=True) or {}
    contact = _normalize_contact(str(data.get("contact") or ""))
    purpose = (data.get("purpose") or "web_login").strip() or "web_login"
    otp = str(data.get("otp") or "").strip()

    if not contact:
        return jsonify({"ok": False, "error": "missing_contact"}), 400
    if not otp:
        return jsonify({"ok": False, "error": "missing_otp"}), 400

    code_hash = _otp_hash(contact, purpose, otp)

    # Validate OTP (latest, not used, not expired)
    try:
        q = (
            _sb()
            .table(WEB_OTP_TABLE)
            .select(f"id,{OTP_COL_EXPIRES_AT},{OTP_COL_USED}")
            .eq(OTP_COL_CONTACT, contact)
            .eq(OTP_COL_PURPOSE, purpose)
            .eq(OTP_COL_CODE_HASH, code_hash)
            .eq(OTP_COL_USED, False)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )

        # handle return-style errors
        resp_err = _extract_response_error(q)
        if resp_err:
            print(f"[web_auth] verify_otp lookup returned error: {resp_err}")
            if ENV == "dev" or WEB_AUTH_DEBUG:
                return jsonify({"ok": False, "error": "otp_lookup_failed", "supabase": resp_err}), 500
            return jsonify({"ok": False, "error": "otp_lookup_failed"}), 500

        rows = (q.data or []) if hasattr(q, "data") else []
    except Exception as e:
        err = _extract_supabase_error(e)
        print(f"[web_auth] verify_otp lookup failed: {err}")
        if ENV == "dev" or WEB_AUTH_DEBUG:
            return jsonify({"ok": False, "error": "otp_lookup_failed", "supabase": err}), 500
        return jsonify({"ok": False, "error": "otp_lookup_failed"}), 500

    if not rows:
        return jsonify({"ok": False, "error": "invalid_otp"}), 401

    row = rows[0]
    exp_raw = (row.get(OTP_COL_EXPIRES_AT) or "").replace("Z", "+00:00")
    try:
        exp = datetime.fromisoformat(exp_raw)
    except Exception:
        return jsonify({"ok": False, "error": "otp_expiry_parse_failed"}), 500

    if _now_utc() > exp:
        # mark used best-effort
        try:
            _sb().table(WEB_OTP_TABLE).update(
                {OTP_COL_USED: True, OTP_COL_USED_AT: _now_utc().isoformat().replace("+00:00", "Z")}
            ).eq("id", row.get("id")).execute()
        except Exception:
            pass
        return jsonify({"ok": False, "error": "otp_expired"}), 401

    # mark OTP as used
    try:
        _sb().table(WEB_OTP_TABLE).update(
            {OTP_COL_USED: True, OTP_COL_USED_AT: _now_utc().isoformat().replace("+00:00", "Z")}
        ).eq("id", row.get("id")).execute()
    except Exception:
        pass

    # Ensure account exists
    account_id = _upsert_account_for_contact(contact)
    if not account_id:
        return jsonify({"ok": False, "error": "account_create_failed"}), 500

    # Create session token + store session row
    raw_token = secrets.token_hex(32)
    expires_at = _now_utc() + timedelta(days=WEB_SESSION_TTL_DAYS)

    try:
        ins = _sb().table(WEB_TOKEN_TABLE).insert(
            {
                "token_hash": _token_hash(raw_token),
                "account_id": account_id,
                "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
                "revoked": False,
                "last_seen_at": _now_utc().isoformat().replace("+00:00", "Z"),
            }
        ).execute()

        resp_err = _extract_response_error(ins)
        if resp_err:
            print(f"[web_auth] session insert returned error: {resp_err}")
            if ENV == "dev" or WEB_AUTH_DEBUG:
                return jsonify({"ok": False, "error": "session_store_failed", "supabase": resp_err}), 500
            return jsonify({"ok": False, "error": "session_store_failed"}), 500

    except Exception as e:
        err = _extract_supabase_error(e)
        print(f"[web_auth] session insert failed: {err}")
        if ENV == "dev" or WEB_AUTH_DEBUG:
            return jsonify({"ok": False, "error": "session_store_failed", "supabase": err}), 500
        return jsonify({"ok": False, "error": "session_store_failed"}), 500

    return jsonify(
        {
            "ok": True,
            "mode": "real",
            "token": raw_token,
            "account_id": account_id,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        }
    )


@bp.get("/me")
@bp.get("/web/auth/me")
@require_auth_plus
def me():
    account_id = getattr(g, "account_id", None)
    if not account_id:
        return jsonify({"ok": False, "error": "missing_account"}), 401

    try:
        res = (
            _sb()
            .table("accounts")
            .select("account_id, provider, provider_user_id, display_name, phone, created_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )

        resp_err = _extract_response_error(res)
        if resp_err:
            print(f"[web_auth] /me account lookup returned error: {resp_err}")
            if ENV == "dev" or WEB_AUTH_DEBUG:
                return jsonify({"ok": False, "error": "account_lookup_failed", "supabase": resp_err}), 500
            return jsonify({"ok": False, "error": "account_lookup_failed"}), 500

        rows = (res.data or []) if hasattr(res, "data") else []
        if not rows:
            return jsonify({"ok": False, "error": "account_not_found"}), 404
        return jsonify({"ok": True, "account": rows[0]})

    except Exception as e:
        err = _extract_supabase_error(e)
        print(f"[web_auth] /me account lookup failed: {err}")
        if ENV == "dev" or WEB_AUTH_DEBUG:
            return jsonify({"ok": False, "error": "account_lookup_failed", "supabase": err}), 500
        return jsonify({"ok": False, "error": "account_lookup_failed"}), 500
