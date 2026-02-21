# app/routes/web_auth.py
from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request, g

from app.core.supabase_client import supabase
from app.core.auth import require_auth_plus, token_hash, auth_debug_snapshot
from app.core.config import WEB_AUTH_ENABLED, WEB_TOKEN_TABLE, WEB_TOKEN_PEPPER
from app.services.email_service import send_email_otp, smtp_is_configured, smtp_debug_snapshot

bp = Blueprint("web_auth", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


ENV = _env("ENV", "prod").lower()

# allow explicit switch for dev-otp return (safer than relying on ENV alone)
WEB_DEV_RETURN_OTP = _truthy(os.getenv("WEB_DEV_RETURN_OTP", "0")) or (ENV == "dev")
WEB_AUTH_DEBUG = _truthy(os.getenv("WEB_AUTH_DEBUG", "0"))

WEB_OTP_TABLE = _env("WEB_OTP_TABLE", "web_otps")
WEB_OTP_PEPPER = _env("WEB_OTP_PEPPER", (os.getenv("WEB_TOKEN_PEPPER", WEB_TOKEN_PEPPER) or WEB_TOKEN_PEPPER))

WEB_SESSION_TTL_DAYS = int(_env("WEB_SESSION_TTL_DAYS", "30") or "30")
WEB_OTP_TTL_MINUTES = int(_env("WEB_OTP_TTL_MINUTES", "10") or "10")


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


def _debug_payload(extra: Optional[dict] = None) -> dict:
    if not WEB_AUTH_DEBUG:
        return {}
    base = {
        "env": ENV,
        "web_auth_enabled": bool(WEB_AUTH_ENABLED),
        "otp_table": WEB_OTP_TABLE,
        "token_table": (os.getenv("WEB_TOKEN_TABLE", WEB_TOKEN_TABLE) or WEB_TOKEN_TABLE),
        "smtp_configured": smtp_is_configured(),
        "smtp": smtp_debug_snapshot(),
        "auth": auth_debug_snapshot(),
        "otp_pepper_len": len(WEB_OTP_PEPPER or ""),
        "otp_pepper_prefix_sha256": _sha256_hex(WEB_OTP_PEPPER or "")[:12],
    }
    if extra:
        base.update(extra)
    return {"debug": base}


def _upsert_account_for_contact(contact: str) -> Dict[str, Any]:
    """
    Returns { ok: True, account_id } or { ok: False, error, detail? }
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
        rows = res.data or []
        if rows:
            return {"ok": True, "account_id": rows[0].get("account_id")}

        insert_res = (
            _sb()
            .table("accounts")
            .insert({
                "provider": "web",
                "provider_user_id": contact,
                "display_name": contact,
                "phone": contact,
            })
            .execute()
        )
        inserted = insert_res.data or []
        if inserted and inserted[0].get("account_id"):
            return {"ok": True, "account_id": inserted[0].get("account_id")}

        return {"ok": False, "error": "account_insert_returned_empty"}

    except Exception as e:
        out = {"ok": False, "error": "account_create_failed"}
        if WEB_AUTH_DEBUG:
            out["detail"] = f"{type(e).__name__}:{str(e)[:180]}"
        return out


@bp.post("/request-otp")
@bp.post("/web/auth/request-otp")
def request_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled", **_debug_payload()}), 403

    data: Dict[str, Any] = request.get_json(silent=True) or {}

    contact = _normalize_contact(str(data.get("contact") or ""))
    purpose = (data.get("purpose") or "web_login").strip()

    # Optional explicit email destination
    email_to = (str(data.get("email") or "") or "").strip().lower()

    if not contact:
        return jsonify({"ok": False, "error": "missing_contact", **_debug_payload()}), 400

    otp = f"{secrets.randbelow(1000000):06d}"
    expires_at = _now_utc() + timedelta(minutes=WEB_OTP_TTL_MINUTES)

    # Store OTP hash
    try:
        _sb().table(WEB_OTP_TABLE).insert({
            "contact": contact,
            "purpose": purpose,
            "code_hash": _otp_hash(contact, purpose, otp),
            "expires_at": expires_at.isoformat(),
            "used": False,
        }).execute()
    except Exception as e:
        payload = {"ok": False, "error": "otp_store_failed"}
        if WEB_AUTH_DEBUG:
            payload["detail"] = f"{type(e).__name__}:{str(e)[:180]}"
        payload.update(_debug_payload())
        return jsonify(payload), 500

    # Decide email destination
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

    resp.update(_debug_payload())
    return jsonify(resp)


@bp.post("/verify-otp")
@bp.post("/web/auth/verify-otp")
def verify_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled", **_debug_payload()}), 403

    data: Dict[str, Any] = request.get_json(silent=True) or {}

    contact = _normalize_contact(str(data.get("contact") or ""))
    purpose = (data.get("purpose") or "web_login").strip()
    otp = str(data.get("otp") or "").strip()

    if not contact or not otp:
        return jsonify({"ok": False, "error": "missing_contact_or_otp", **_debug_payload()}), 400

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
            .limit(1)
            .execute()
        )
    except Exception as e:
        payload = {"ok": False, "error": "otp_lookup_failed"}
        if WEB_AUTH_DEBUG:
            payload["detail"] = f"{type(e).__name__}:{str(e)[:180]}"
        payload.update(_debug_payload())
        return jsonify(payload), 500

    rows = q.data or []
    if not rows:
        return jsonify({"ok": False, "error": "invalid_otp", **_debug_payload()}), 401

    row = rows[0]
    try:
        exp = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if _now_utc() > exp.astimezone(timezone.utc):
            return jsonify({"ok": False, "error": "otp_expired", **_debug_payload()}), 401
    except Exception:
        return jsonify({"ok": False, "error": "otp_expired", **_debug_payload()}), 401

    # mark used
    try:
        _sb().table(WEB_OTP_TABLE).update({"used": True}).eq("id", row["id"]).execute()
    except Exception:
        # don't block login if mark-used fails
        pass

    acct = _upsert_account_for_contact(contact)
    if not acct.get("ok"):
        payload = {"ok": False, "error": acct.get("error", "account_create_failed")}
        if WEB_AUTH_DEBUG and acct.get("detail"):
            payload["detail"] = acct["detail"]
        payload.update(_debug_payload())
        return jsonify(payload), 500

    account_id = acct["account_id"]

    raw_token = secrets.token_hex(32)
    expires_at = _now_utc() + timedelta(days=WEB_SESSION_TTL_DAYS)

    # IMPORTANT: use SAME token hashing as require_auth_plus()
    th = token_hash(raw_token)
    table = (os.getenv("WEB_TOKEN_TABLE", WEB_TOKEN_TABLE) or WEB_TOKEN_TABLE).strip()

    try:
        _sb().table(table).insert({
            "token_hash": th,
            "account_id": account_id,
            "expires_at": expires_at.isoformat(),
            "revoked": False,
            "last_seen_at": _now_utc().isoformat(),
        }).execute()
    except Exception as e:
        payload = {"ok": False, "error": "token_insert_failed"}
        if WEB_AUTH_DEBUG:
            payload["detail"] = f"{type(e).__name__}:{str(e)[:180]}"
            payload["token_hash_prefix"] = th[:12]
        payload.update(_debug_payload({"token_table": table}))
        return jsonify(payload), 500

    resp = {
        "ok": True,
        "token": raw_token,
        "account_id": account_id,
        "expires_at": expires_at.isoformat(),
    }
    resp.update(_debug_payload({"token_hash_prefix": th[:12]}))
    return jsonify(resp)


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
