# app/routes/web_auth.py
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, jsonify, request, g

from app.core.supabase_client import supabase
from app.core.auth import require_auth_plus
from app.core.config import (
    WEB_AUTH_ENABLED,
    WEB_TOKEN_TABLE,
    WEB_TOKEN_PEPPER,
)

from app.services.email_service import send_email_otp, smtp_is_configured

bp = Blueprint("web_auth", __name__)

# -------------------------------------------------
# Helpers
# -------------------------------------------------

def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


ENV = _env("ENV", "prod").lower()

WEB_OTP_TABLE = _env("WEB_OTP_TABLE", "web_otps")
WEB_OTP_PEPPER = _env("WEB_OTP_PEPPER", WEB_TOKEN_PEPPER)
WEB_SESSION_TTL_DAYS = int(_env("WEB_SESSION_TTL_DAYS", "30") or "30")
WEB_OTP_TTL_MINUTES = int(_env("WEB_OTP_TTL_MINUTES", "10") or "10")

# Debug toggle (safe: DO NOT expose secrets, only health flags + error codes)
WEB_AUTH_DEBUG = (_env("WEB_AUTH_DEBUG", "0") == "1")

# Dev-only return OTP to API caller (disable in prod)
WEB_DEV_RETURN_OTP = (ENV == "dev")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _otp_hash(contact: str, purpose: str, otp: str) -> str:
    return _sha256_hex(f"{WEB_OTP_PEPPER}:{contact}:{purpose}:{otp}")


def _token_hash(raw_token: str) -> str:
    # MUST match app/core/auth.py hashing logic
    return _sha256_hex(f"{WEB_TOKEN_PEPPER}:{raw_token}")


def _normalize_contact(v: str) -> str:
    v = (v or "").strip()
    if not v:
        return ""
    # email contact: normalize to lowercase
    if "@" in v:
        return v.lower()
    # phone normalization
    if v.startswith("0"):
        return "+234" + v[1:]
    if v.startswith("234"):
        return "+" + v
    return v


def _is_email(v: str) -> bool:
    v = (v or "").strip()
    return ("@" in v) and ("." in v)


def _safe_debug_info() -> Dict[str, Any]:
    # do not leak actual passwords/keys
    pepper = WEB_TOKEN_PEPPER or ""
    otppep = WEB_OTP_PEPPER or ""
    return {
        "env": ENV,
        "auth": {
            "web_auth_enabled": bool(WEB_AUTH_ENABLED),
            "web_token_table": WEB_TOKEN_TABLE,
            "pepper_len": len(pepper),
            "pepper_prefix_sha256": _sha256_hex(pepper)[:12] if pepper else "",
            "otp_pepper_len": len(otppep),
            "otp_pepper_prefix_sha256": _sha256_hex(otppep)[:12] if otppep else "",
        },
        "tables": {
            "otp_table": WEB_OTP_TABLE,
            "token_table": WEB_TOKEN_TABLE,
        },
        "smtp": {
            "smtp_configured": bool(smtp_is_configured()),
        },
    }


def _pg_error_details(e: Exception) -> Dict[str, Any]:
    """
    Supabase python clients can surface errors in different shapes.
    We normalize to a predictable {code,message,details,hint} bundle when possible.
    """
    out: Dict[str, Any] = {"type": type(e).__name__}
    s = str(e)
    out["raw"] = s[:500]  # prevent huge responses

    # Common PostgREST style: APIError: {'code': '23502', 'details': ..., 'hint': ..., 'message': ...}
    if "APIError:" in s and "{" in s and "}" in s:
        out["note"] = "looks_like_postgrest_apierror"
    return out


def _has_column(table: str, col: str) -> bool:
    """
    Best-effort: attempt a select with the column; if it errors, assume missing.
    """
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def _account_pk_column() -> str:
    """
    Decide whether your accounts table uses 'account_id' or 'id' as identifier.
    Prefer account_id.
    """
    if _has_column("accounts", "account_id"):
        return "account_id"
    if _has_column("accounts", "id"):
        return "id"
    # fallback guess
    return "account_id"


# -------------------------------------------------
# Account Creation (web accounts)
# -------------------------------------------------

def _upsert_account_for_contact(contact: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Returns (account_id, debug_detail_if_any)
    """
    pk = _account_pk_column()
    dbg: Dict[str, Any] = {"pk": pk}

    try:
        # 1) check if exists
        res = (
            _sb()
            .table("accounts")
            .select(pk)
            .eq("provider", "web")
            .eq("provider_user_id", contact)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows and rows[0].get(pk):
            return str(rows[0][pk]), (dbg if WEB_AUTH_DEBUG else None)

        # 2) build insert payload ONLY with columns that exist
        payload: Dict[str, Any] = {
            "provider": "web",
            "provider_user_id": contact,
        }

        # common identity/display fields
        if _has_column("accounts", "display_name"):
            payload["display_name"] = contact
        elif _has_column("accounts", "name"):
            payload["name"] = contact

        # contact fields (some schemas use email/phone separately)
        if _is_email(contact):
            if _has_column("accounts", "email"):
                payload["email"] = contact
            # keep phone only if column exists AND you want it
            if _has_column("accounts", "phone"):
                payload["phone"] = contact  # optional; harmless if nullable
        else:
            if _has_column("accounts", "phone"):
                payload["phone"] = contact
            if _has_column("accounts", "email"):
                payload["email"] = None  # leave unset; avoid forcing NULL into NOT NULL email

        # timestamps if your table expects them
        if _has_column("accounts", "created_at"):
            payload.setdefault("created_at", _now_utc().isoformat())
        if _has_column("accounts", "updated_at"):
            payload.setdefault("updated_at", _now_utc().isoformat())

        dbg["insert_payload_keys"] = sorted(payload.keys())

        insert_res = _sb().table("accounts").insert(payload).execute()
        inserted = insert_res.data or []
        if inserted and inserted[0].get(pk):
            return str(inserted[0][pk]), (dbg if WEB_AUTH_DEBUG else None)

        # If insert succeeded but did not return pk (RLS/select restriction), re-query:
        res2 = (
            _sb()
            .table("accounts")
            .select(pk)
            .eq("provider", "web")
            .eq("provider_user_id", contact)
            .limit(1)
            .execute()
        )
        rows2 = res2.data or []
        if rows2 and rows2[0].get(pk):
            return str(rows2[0][pk]), (dbg if WEB_AUTH_DEBUG else None)

        dbg["error"] = "account_insert_no_pk_returned"
        return None, (dbg if WEB_AUTH_DEBUG else None)

    except Exception as e:
        dbg["exception"] = _pg_error_details(e)
        return None, (dbg if WEB_AUTH_DEBUG else None)


# -------------------------------------------------
# REQUEST OTP
# -------------------------------------------------

@bp.post("/request-otp")
@bp.post("/web/auth/request-otp")
def request_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled"}), 403

    data: Dict[str, Any] = request.get_json(silent=True) or {}

    contact = _normalize_contact(str(data.get("contact") or ""))
    purpose = (data.get("purpose") or "web_login").strip()
    email_to = (str(data.get("email") or "") or "").strip().lower()

    if not contact:
        return jsonify({"ok": False, "error": "missing_contact"}), 400

    otp = f"{secrets.randbelow(1000000):06d}"
    expires_at = _now_utc() + timedelta(minutes=WEB_OTP_TTL_MINUTES)

    try:
        _sb().table(WEB_OTP_TABLE).insert({
            "contact": contact,
            "purpose": purpose,
            "code_hash": _otp_hash(contact, purpose, otp),
            "expires_at": expires_at.isoformat(),
            "used": False,
        }).execute()
    except Exception as e:
        resp = {"ok": False, "error": "otp_store_failed"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = {**_safe_debug_info(), "detail": _pg_error_details(e)}
        return jsonify(resp), 500

    sent_email = False
    email_err: Optional[str] = None

    dest_email = ""
    if _is_email(contact):
        dest_email = contact
    elif _is_email(email_to):
        dest_email = email_to

    if dest_email:
        email_err = send_email_otp(
            to_email=dest_email,
            otp=otp,
            purpose=purpose,
            ttl_minutes=WEB_OTP_TTL_MINUTES,
        )
        sent_email = (email_err is None)

    resp: Dict[str, Any] = {
        "ok": True,
        "ttl_minutes": WEB_OTP_TTL_MINUTES,
        "email_sent": bool(sent_email),
        "email_to": dest_email or (contact if _is_email(contact) else None),
    }
    if dest_email and email_err:
        resp["email_error"] = email_err

    if WEB_AUTH_DEBUG:
        resp["debug"] = _safe_debug_info()

    if WEB_DEV_RETURN_OTP:
        resp["dev_otp"] = otp
        resp["smtp_configured"] = smtp_is_configured()

    return jsonify(resp)


# -------------------------------------------------
# VERIFY OTP
# -------------------------------------------------

@bp.post("/verify-otp")
@bp.post("/web/auth/verify-otp")
def verify_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled"}), 403

    data: Dict[str, Any] = request.get_json(silent=True) or {}

    contact = _normalize_contact(str(data.get("contact") or ""))
    purpose = (data.get("purpose") or "web_login").strip()
    otp = str(data.get("otp") or "").strip()

    if not contact or not otp:
        resp = {"ok": False, "error": "invalid_request"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = _safe_debug_info()
        return jsonify(resp), 400

    code_hash = _otp_hash(contact, purpose, otp)

    try:
        q = (
            _sb()
            .table(WEB_OTP_TABLE)
            .select("*")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .eq("code_hash", code_hash)
            .eq("used", False)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
    except Exception as e:
        resp = {"ok": False, "error": "otp_lookup_failed"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = {**_safe_debug_info(), "detail": _pg_error_details(e)}
        return jsonify(resp), 500

    rows = q.data or []
    if not rows:
        resp = {"ok": False, "error": "invalid_otp"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = _safe_debug_info()
        return jsonify(resp), 401

    row = rows[0]
    try:
        exp = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if _now_utc() > exp.astimezone(timezone.utc):
            return jsonify({"ok": False, "error": "otp_expired"}), 401
    except Exception:
        return jsonify({"ok": False, "error": "otp_expired"}), 401

    # mark used
    try:
        _sb().table(WEB_OTP_TABLE).update({"used": True, "used_at": _now_utc().isoformat()}).eq("id", row["id"]).execute()
    except Exception:
        # not fatal
        pass

    account_id, account_dbg = _upsert_account_for_contact(contact)
    if not account_id:
        resp = {"ok": False, "error": "account_create_failed"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = {**_safe_debug_info(), "detail": account_dbg}
        return jsonify(resp), 500

    raw_token = secrets.token_hex(32)
    expires_at = _now_utc() + timedelta(days=WEB_SESSION_TTL_DAYS)

    try:
        _sb().table(WEB_TOKEN_TABLE).insert({
            "token_hash": _token_hash(raw_token),
            "account_id": account_id,
            "expires_at": expires_at.isoformat(),
            "revoked": False,
            "created_at": _now_utc().isoformat() if _has_column(WEB_TOKEN_TABLE, "created_at") else None,
            "last_seen_at": _now_utc().isoformat() if _has_column(WEB_TOKEN_TABLE, "last_seen_at") else None,
        }).execute()
    except Exception as e:
        resp = {"ok": False, "error": "token_issue_failed"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = {**_safe_debug_info(), "detail": _pg_error_details(e), "account_id": account_id}
        return jsonify(resp), 500

    out = {
        "ok": True,
        "token": raw_token,
        "account_id": account_id,
        "expires_at": expires_at.isoformat(),
    }
    if WEB_AUTH_DEBUG:
        out["debug"] = {**_safe_debug_info(), "account": account_dbg}

    return jsonify(out)


# -------------------------------------------------
# ME
# -------------------------------------------------

@bp.get("/me")
@bp.get("/web/auth/me")
@require_auth_plus
def me():
    account_id = g.account_id

    # Most systems use accounts.account_id, but some use id.
    # Try account_id first, fallback to id.
    try_cols = ["account_id", "id"]

    for col in try_cols:
        try:
            if not _has_column("accounts", col):
                continue
            res = (
                _sb()
                .table("accounts")
                .select("*")
                .eq(col, account_id)
                .limit(1)
                .execute()
            )
            rows = res.data or []
            if rows:
                return jsonify({"ok": True, "account": rows[0]})
        except Exception:
            continue

    resp: Dict[str, Any] = {"ok": False}
    if WEB_AUTH_DEBUG:
        resp["debug"] = _safe_debug_info()
        resp["debug"]["me_lookup_account_id"] = account_id
    return jsonify(resp), 404
