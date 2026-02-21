# app/routes/web_auth.py
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request, make_response

from app.core.supabase_client import supabase
from app.core.auth import token_hash
from app.services.web_tokens_service import revoke_token
from app.services.email_service import send_email_otp, smtp_is_configured

bp = Blueprint("web_auth", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


# -------------------------
# Cookie config (Option A)
# -------------------------
def _cookie_name() -> str:
    # Prefer the new name; fall back to old envs if present
    return (
        _env("WEB_AUTH_COOKIE_NAME")
        or _env("WEB_COOKIE_NAME")
        or _env("WEB_COOKIE_NAME_LEGACY")
        or "ntg_session"
    ).strip()


def _cookie_secure() -> bool:
    # For SameSite=None you MUST be Secure (true) on HTTPS
    return _env("WEB_AUTH_COOKIE_SECURE", _env("COOKIE_SECURE", "1")) == "1"


def _cookie_samesite() -> str:
    # Cross-site (Vercel -> Koyeb) requires SameSite=None + Secure
    return (_env("WEB_AUTH_COOKIE_SAMESITE", _env("COOKIE_SAMESITE", "None")) or "None").strip()


def _cookie_domain() -> Optional[str]:
    # Usually leave empty for cross-site (Vercel <-> Koyeb), unless you know you need it.
    v = _env("WEB_AUTH_COOKIE_DOMAIN", _env("COOKIE_DOMAIN", "")).strip()
    return v or None


ENV = _env("ENV", "prod").lower()

WEB_AUTH_ENABLED = (_env("WEB_AUTH_ENABLED", "1") == "1")
WEB_AUTH_DEBUG = (_env("WEB_AUTH_DEBUG", "0") == "1")

WEB_OTP_TABLE = _env("WEB_OTP_TABLE", "web_otps")
WEB_TOKEN_TABLE = _env("WEB_TOKEN_TABLE", "web_sessions")

WEB_OTP_TTL_MINUTES = int(_env("WEB_OTP_TTL_MINUTES", "10") or "10")
WEB_SESSION_TTL_DAYS = int(_env("WEB_SESSION_TTL_DAYS", "30") or "30")

WEB_OTP_PEPPER = _env("WEB_OTP_PEPPER", _env("WEB_TOKEN_PEPPER", ""))

# Dev-only OTP return (keep your current behavior)
WEB_DEV_RETURN_OTP = (_env("WEB_DEV_RETURN_OTP", "0") == "1") or (ENV == "dev")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _otp_hash(contact: str, purpose: str, otp: str) -> str:
    return _sha256_hex(f"{WEB_OTP_PEPPER}:{contact}:{purpose}:{otp}")


def _normalize_contact(v: str) -> str:
    v = (v or "").strip()
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
    v = (v or "").strip()
    return ("@" in v) and ("." in v)


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def _safe_debug_info() -> Dict[str, Any]:
    return {
        "env": ENV,
        "tables": {"otp_table": WEB_OTP_TABLE, "token_table": WEB_TOKEN_TABLE},
        "cookie": {
            "name": _cookie_name(),
            "secure": _cookie_secure(),
            "samesite": _cookie_samesite(),
            "domain": _cookie_domain() or "",
        },
        "smtp_configured": bool(smtp_is_configured()),
    }


def _account_pk_column() -> str:
    if _has_column("accounts", "account_id"):
        return "account_id"
    if _has_column("accounts", "id"):
        return "id"
    return "account_id"


def _upsert_account_for_contact(contact: str) -> Optional[str]:
    pk = _account_pk_column()

    # 1) exists?
    try:
        res = (
            _sb()
            .table("accounts")
            .select(pk)
            .eq("provider", "web")
            .eq("provider_user_id", contact)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        if rows and rows[0].get(pk):
            return str(rows[0][pk])
    except Exception:
        pass

    # 2) insert minimal safe fields
    payload: Dict[str, Any] = {
        "provider": "web",
        "provider_user_id": contact,
    }
    if _has_column("accounts", "display_name"):
        payload["display_name"] = contact
    if _has_column("accounts", "phone"):
        payload["phone"] = contact if not _is_email(contact) else None

    try:
        ins = _sb().table("accounts").insert(payload).execute()
        inserted = (ins.data or []) if hasattr(ins, "data") else []
        if inserted and inserted[0].get(pk):
            return str(inserted[0][pk])
    except Exception:
        pass

    # fallback re-query
    try:
        res2 = (
            _sb()
            .table("accounts")
            .select(pk)
            .eq("provider", "web")
            .eq("provider_user_id", contact)
            .limit(1)
            .execute()
        )
        rows2 = (res2.data or []) if hasattr(res2, "data") else []
        if rows2 and rows2[0].get(pk):
            return str(rows2[0][pk])
    except Exception:
        pass

    return None


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
    purpose = (str(data.get("purpose") or "web_login")).strip()
    email_to = (str(data.get("email") or "") or "").strip().lower()

    if not contact:
        return jsonify({"ok": False, "error": "missing_contact"}), 400

    otp = f"{secrets.randbelow(1000000):06d}"
    expires_at = _now_utc() + timedelta(minutes=WEB_OTP_TTL_MINUTES)

    try:
        _sb().table(WEB_OTP_TABLE).insert(
            {
                "contact": contact,
                "purpose": purpose,
                "code_hash": _otp_hash(contact, purpose, otp),
                "expires_at": expires_at.isoformat(),
                "used": False,
            }
        ).execute()
    except Exception:
        resp = {"ok": False, "error": "otp_store_failed"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = _safe_debug_info()
        return jsonify(resp), 500

    # Determine email destination
    dest_email = ""
    if _is_email(contact):
        dest_email = contact
    elif _is_email(email_to):
        dest_email = email_to

    sent_email = False
    email_err: Optional[str] = None
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
        "email_to": dest_email or None,
    }

    if dest_email and email_err:
        resp["email_error"] = email_err

    if WEB_DEV_RETURN_OTP:
        resp["dev_otp"] = otp
        resp["smtp_configured"] = smtp_is_configured()

    if WEB_AUTH_DEBUG:
        resp["debug"] = _safe_debug_info()

    # IMPORTANT: request_otp does NOT set cookies.
    return jsonify(resp), 200


# -------------------------------------------------
# VERIFY OTP (SETS COOKIE)
# -------------------------------------------------
@bp.post("/verify-otp")
@bp.post("/web/auth/verify-otp")
def verify_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled"}), 403

    data: Dict[str, Any] = request.get_json(silent=True) or {}

    contact = _normalize_contact(str(data.get("contact") or ""))
    purpose = (str(data.get("purpose") or "web_login")).strip()
    otp = str(data.get("otp") or "").strip()

    if not contact or not otp:
        resp = {"ok": False, "error": "invalid_request"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = _safe_debug_info()
        return jsonify(resp), 400

    code_hash = _otp_hash(contact, purpose, otp)

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
    rows = (q.data or []) if hasattr(q, "data") else []
    if not rows:
        resp = {"ok": False, "error": "invalid_otp"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = _safe_debug_info()
        return jsonify(resp), 401

    row = rows[0]

    # expiry check
    try:
        exp = datetime.fromisoformat(str(row.get("expires_at")).replace("Z", "+00:00"))
        if _now_utc() > exp.astimezone(timezone.utc):
            return jsonify({"ok": False, "error": "otp_expired"}), 401
    except Exception:
        return jsonify({"ok": False, "error": "otp_expired"}), 401

    # mark used (best effort)
    try:
        if "id" in row:
            _sb().table(WEB_OTP_TABLE).update(
                {"used": True, "used_at": _now_utc().isoformat()}
            ).eq("id", row["id"]).execute()
    except Exception:
        pass

    account_id = _upsert_account_for_contact(contact)
    if not account_id:
        resp = {"ok": False, "error": "account_create_failed"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = _safe_debug_info()
        return jsonify(resp), 500

    # Create session token row
    raw_token = secrets.token_hex(32)
    expires_at = _now_utc() + timedelta(days=WEB_SESSION_TTL_DAYS)

    insert_payload: Dict[str, Any] = {
        "token_hash": token_hash(raw_token),
        "account_id": account_id,
        "expires_at": expires_at.isoformat(),
    }

    # Support both revoke schemas
    if _has_column(WEB_TOKEN_TABLE, "revoked"):
        insert_payload["revoked"] = False
    if _has_column(WEB_TOKEN_TABLE, "revoked_at"):
        insert_payload["revoked_at"] = None

    if _has_column(WEB_TOKEN_TABLE, "created_at"):
        insert_payload["created_at"] = _now_utc().isoformat()
    if _has_column(WEB_TOKEN_TABLE, "last_seen_at"):
        insert_payload["last_seen_at"] = _now_utc().isoformat()

    try:
        _sb().table(WEB_TOKEN_TABLE).insert(insert_payload).execute()
    except Exception:
        resp = {"ok": False, "error": "token_issue_failed"}
        if WEB_AUTH_DEBUG:
            resp["debug"] = _safe_debug_info()
        return jsonify(resp), 500

    out: Dict[str, Any] = {
        "ok": True,
        "token": raw_token,  # keep returning so PowerShell scripts still work
        "account_id": account_id,
        "expires_at": expires_at.isoformat(),
        "auth_mode": "cookie+bearer",
    }
    if WEB_AUTH_DEBUG:
        out["debug"] = _safe_debug_info()

    resp = make_response(jsonify(out), 200)
    resp.set_cookie(
        _cookie_name(),
        raw_token,
        httponly=True,
        secure=_cookie_secure(),
        samesite=_cookie_samesite(),  # "None" for Vercel cross-site
        domain=_cookie_domain(),
        path="/",
        max_age=WEB_SESSION_TTL_DAYS * 24 * 60 * 60,
    )
    return resp


# -------------------------------------------------
# LOGOUT (revoke + clear cookie)
# -------------------------------------------------
@bp.post("/logout")
@bp.post("/web/auth/logout")
def logout():
    # cookie first
    raw = (request.cookies.get(_cookie_name()) or "").strip()

    # bearer fallback
    if not raw:
        auth = (request.headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            raw = auth[7:].strip()

    if raw:
        try:
            revoke_token(raw, table=WEB_TOKEN_TABLE)
        except Exception:
            pass

    resp = make_response(jsonify({"ok": True}), 200)
    resp.delete_cookie(_cookie_name(), domain=_cookie_domain(), path="/")
    return resp
