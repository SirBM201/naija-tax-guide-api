# app/routes/web_auth.py
from __future__ import annotations

import hashlib
import os
import secrets
import traceback
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
# Helpers / Debug
# -------------------------------------------------

def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _dbg_enabled() -> bool:
    # Turn ON temporarily on Koyeb: WEB_AUTH_DEBUG=1
    return _truthy(os.getenv("WEB_AUTH_DEBUG"))


def _dbg(msg: str) -> None:
    if _dbg_enabled():
        print(msg, flush=True)


def _safe_exc(e: Exception) -> Dict[str, Any]:
    """
    Make Supabase/PostgREST errors readable without leaking secrets/tokens.
    """
    out: Dict[str, Any] = {
        "type": type(e).__name__,
        "msg": str(e)[:400],
    }

    # PostgrestAPIError often has .details / .code / .hint
    for k in ("code", "details", "hint", "message"):
        if hasattr(e, k):
            try:
                out[k] = getattr(e, k)
            except Exception:
                pass

    if _dbg_enabled():
        out["trace"] = traceback.format_exc()[-1200:]  # last part only
    return out


ENV = _env("ENV", "prod").lower()
WEB_OTP_TABLE = _env("WEB_OTP_TABLE", "web_otps")
WEB_OTP_PEPPER = _env("WEB_OTP_PEPPER", WEB_TOKEN_PEPPER)
WEB_SESSION_TTL_DAYS = int(_env("WEB_SESSION_TTL_DAYS", "30") or "30")
WEB_OTP_TTL_MINUTES = int(_env("WEB_OTP_TTL_MINUTES", "10") or "10")

# DEV-only return OTP to API caller (you already enabled via ENV=dev + WEB_DEV_RETURN_OTP=1 in env)
WEB_DEV_RETURN_OTP = _truthy(os.getenv("WEB_DEV_RETURN_OTP")) or (ENV == "dev")


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
    # email: lower-case only
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


def _has_column(table: str, col: str) -> bool:
    """
    Best-effort: try selecting the column. If it errors, assume missing.
    """
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def _pick_account_id(row: Dict[str, Any]) -> Optional[str]:
    """
    Some schemas use account_id, others use id.
    """
    return (row.get("account_id") or row.get("id") or None)


# -------------------------------------------------
# Account Creation (web accounts)
# -------------------------------------------------

def _upsert_account_for_contact(contact: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Returns (account_id, debug_info_if_failed)
    """
    debug: Dict[str, Any] = {"contact": contact, "provider": "web"}

    try:
        # 1) Lookup (try both account_id and id)
        sel = "account_id,id,provider,provider_user_id,display_name,phone,email,created_at"
        try:
            res = (
                _sb()
                .table("accounts")
                .select(sel)
                .eq("provider", "web")
                .eq("provider_user_id", contact)
                .limit(1)
                .execute()
            )
        except Exception as e:
            debug["lookup_error"] = _safe_exc(e)
            # continue to insert attempt (maybe select blocked by RLS)
            res = None

        rows = []
        if res is not None and hasattr(res, "data"):
            rows = res.data or []

        if rows:
            acc_id = _pick_account_id(rows[0])
            debug["lookup_found"] = True
            debug["lookup_row_keys"] = list(rows[0].keys())
            return acc_id, None

        debug["lookup_found"] = False

        # 2) Insert new account
        payload: Dict[str, Any] = {
            "provider": "web",
            "provider_user_id": contact,
            "display_name": contact,
        }

        # Optional schema-aware fields (prevents failures when constraints exist)
        if _has_column("accounts", "email") and _is_email(contact):
            payload["email"] = contact

        if _has_column("accounts", "phone"):
            # If email, avoid stuffing into phone if your schema validates phone format
            payload["phone"] = contact if not _is_email(contact) else None

        debug["insert_payload_keys"] = list(payload.keys())

        ins = _sb().table("accounts").insert(payload).execute()
        inserted = getattr(ins, "data", None) or []

        debug["insert_returned_rows"] = len(inserted)
        if not inserted:
            # This often happens when RLS blocks insert using anon key
            debug["insert_empty_data"] = True
            return None, debug

        acc_id = _pick_account_id(inserted[0])
        debug["insert_row_keys"] = list(inserted[0].keys())

        if not acc_id:
            debug["missing_account_id_in_response"] = True
            return None, debug

        return acc_id, None

    except Exception as e:
        debug["fatal_error"] = _safe_exc(e)
        return None, debug


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
        err = _safe_exc(e)
        return jsonify({"ok": False, "error": "otp_store_failed", "debug": err if _dbg_enabled() else None}), 500

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

    resp: Dict[str, Any] = {"ok": True, "ttl_minutes": WEB_OTP_TTL_MINUTES}
    resp["email_sent"] = bool(sent_email)
    if dest_email:
        resp["email_to"] = dest_email
    if dest_email and email_err:
        resp["email_error"] = email_err

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

    # accept both otp and code (to avoid client mismatch)
    otp = str(data.get("otp") or data.get("code") or "").strip()

    if not contact or not otp:
        return jsonify({"ok": False, "error": "missing_contact_or_otp"}), 400

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
        err = _safe_exc(e)
        return jsonify({"ok": False, "error": "otp_lookup_failed", "debug": err if _dbg_enabled() else None}), 500

    rows = q.data or []
    if not rows:
        return jsonify({"ok": False, "error": "invalid_otp"}), 401

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
    except Exception as e:
        # non-fatal, but show in debug if enabled
        _dbg(f"[web_auth] warn: failed to mark otp used: {type(e).__name__}: {str(e)[:160]}")

    # create / fetch account
    account_id, debug_info = _upsert_account_for_contact(contact)
    if not account_id:
        return jsonify({
            "ok": False,
            "error": "account_create_failed",
            "debug": debug_info if _dbg_enabled() else None
        }), 500

    raw_token = secrets.token_hex(32)
    expires_at = _now_utc() + timedelta(days=WEB_SESSION_TTL_DAYS)

    try:
        _sb().table(WEB_TOKEN_TABLE).insert({
            "token_hash": _token_hash(raw_token),
            "account_id": account_id,
            "expires_at": expires_at.isoformat(),
            "revoked": False,
        }).execute()
    except Exception as e:
        err = _safe_exc(e)
        return jsonify({"ok": False, "error": "token_issue_failed", "debug": err if _dbg_enabled() else None}), 500

    return jsonify({
        "ok": True,
        "token": raw_token,
        "account_id": account_id,
        "expires_at": expires_at.isoformat(),
    })


# -------------------------------------------------
# ME
# -------------------------------------------------

@bp.get("/me")
@bp.get("/web/auth/me")
@require_auth_plus
def me():
    account_id = g.account_id

    res = (
        _sb()
        .table("accounts")
        .select("*")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )

    rows = res.data or []
    if not rows:
        return jsonify({"ok": False}), 404

    return jsonify({"ok": True, "account": rows[0]})
