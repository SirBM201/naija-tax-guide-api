# app/routes/web_auth.py
from __future__ import annotations

import hashlib
import os
import secrets
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request, g

from app.core.supabase_client import supabase
from app.core.auth import require_auth_plus
from app.core.config import WEB_AUTH_ENABLED, WEB_TOKEN_TABLE, WEB_TOKEN_PEPPER

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

WEB_OTP_TABLE = _env("WEB_OTP_TABLE", "web_otps")

# IMPORTANT:
# If WEB_OTP_PEPPER isn't set, it falls back to WEB_TOKEN_PEPPER.
# If you accidentally change WEB_TOKEN_PEPPER between deploys/instances,
# old OTPs become unverifiable -> invalid_otp.
WEB_OTP_PEPPER = _env("WEB_OTP_PEPPER", WEB_TOKEN_PEPPER)

WEB_SESSION_TTL_DAYS = int(_env("WEB_SESSION_TTL_DAYS", "30") or "30")
WEB_OTP_TTL_MINUTES = int(_env("WEB_OTP_TTL_MINUTES", "10") or "10")

# NEW:
# You can force dev OTP return even in prod by setting:
# WEB_DEV_RETURN_OTP=1
WEB_DEV_RETURN_OTP = _truthy(_env("WEB_DEV_RETURN_OTP", "0")) or (ENV == "dev")

# NEW:
# Debug logs (safe) when WEB_AUTH_DEBUG=1
WEB_AUTH_DEBUG = _truthy(_env("WEB_AUTH_DEBUG", "0"))


def _dbg(msg: str) -> None:
    if WEB_AUTH_DEBUG:
        print(msg, flush=True)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _otp_hash(contact: str, purpose: str, otp: str) -> str:
    return _sha256_hex(f"{WEB_OTP_PEPPER}:{contact}:{purpose}:{otp}")


def _token_hash(raw_token: str) -> str:
    pepper = (os.getenv("WEB_TOKEN_PEPPER", WEB_TOKEN_PEPPER) or WEB_TOKEN_PEPPER).strip()
    return _sha256_hex(f"{pepper}:{raw_token}")


def _normalize_contact(v: str) -> str:
    v = (v or "").strip()
    if v.startswith("0"):
        return "+234" + v[1:]
    if v.startswith("234"):
        return "+" + v
    return v


def _upsert_account_for_contact(contact: str) -> Optional[str]:
    """
    Ensure account exists for web login.
    NOTE: your DB columns look like `id` (uuid) not `account_id`.
    So we select/return `id`.
    """
    try:
        # Check if already exists
        res = (
            _sb()
            .table("accounts")
            .select("id")
            .eq("provider", "web")
            .eq("provider_user_id", contact.replace("+", ""))  # matches your screenshot: provider_user_id = 234...
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows:
            return rows[0]["id"]

        # Insert WITHOUT id (let DB generate UUID)
        insert_res = (
            _sb()
            .table("accounts")
            .insert(
                {
                    "provider": "web",
                    "provider_user_id": contact.replace("+", ""),
                    "phone_e164": contact.replace("+", ""),
                }
            )
            .execute()
        )

        inserted = insert_res.data or []
        if inserted:
            # Supabase usually returns inserted rows (including id)
            return inserted[0].get("id")

        return None

    except Exception as e:
        _dbg(f"[web_auth] account_create_failed: {type(e).__name__}: {str(e)[:200]}")
        _dbg("[web_auth] traceback:\n" + traceback.format_exc())
        return None


@bp.post("/request-otp")
@bp.post("/web/auth/request-otp")
def request_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled"}), 403

    data: Dict[str, Any] = request.get_json(silent=True) or {}
    contact = _normalize_contact(str(data.get("contact") or ""))
    purpose = (data.get("purpose") or "web_login").strip()

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
    except Exception as e:
        _dbg(f"[web_auth] otp_store_failed: {type(e).__name__}: {str(e)[:200]}")
        _dbg("[web_auth] traceback:\n" + traceback.format_exc())
        return jsonify({"ok": False, "error": "otp_store_failed"}), 500

    # SAFE debug info
    _dbg(
        f"[web_auth] request_otp ok contact={contact} purpose={purpose} "
        f"env={ENV} dev_return={WEB_DEV_RETURN_OTP} pepper_len={len(WEB_OTP_PEPPER)} ttl_min={WEB_OTP_TTL_MINUTES}"
    )

    resp = {"ok": True}

    # Only return OTP when explicitly allowed
    if WEB_DEV_RETURN_OTP:
        resp["dev_otp"] = otp

    # IMPORTANT: In true production, you must send otp via SMS/email here.

    return jsonify(resp)


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
        _dbg(f"[web_auth] invalid_request contact_present={bool(contact)} otp_present={bool(otp)} purpose={purpose}")
        return jsonify({"ok": False, "error": "invalid_request"}), 400

    code_hash = _otp_hash(contact, purpose, otp)

    try:
        # Try match
        q = (
            _sb()
            .table(WEB_OTP_TABLE)
            .select("id, expires_at, used")
            .eq("contact", contact)
            .eq("purpose", purpose)
            .eq("code_hash", code_hash)
            .eq("used", False)
            .limit(1)
            .execute()
        )
        rows = q.data or []

        if not rows:
            # ROOT-CAUSE debug: show last few OTP rows for that contact/purpose
            try:
                recent = (
                    _sb()
                    .table(WEB_OTP_TABLE)
                    .select("id, expires_at, used")
                    .eq("contact", contact)
                    .eq("purpose", purpose)
                    .order("expires_at", desc=True)
                    .limit(3)
                    .execute()
                ).data or []
            except Exception:
                recent = []

            _dbg(
                f"[web_auth] invalid_otp contact={contact} purpose={purpose} "
                f"hash_prefix={code_hash[:12]} env={ENV} dev_return={WEB_DEV_RETURN_OTP} "
                f"pepper_len={len(WEB_OTP_PEPPER)} recent_rows={recent}"
            )
            return jsonify({"ok": False, "error": "invalid_otp"}), 401

        row = rows[0]
        exp_raw = str(row["expires_at"]).replace("Z", "+00:00")
        exp_dt = datetime.fromisoformat(exp_raw).astimezone(timezone.utc)
        if _now_utc() > exp_dt:
            _dbg(f"[web_auth] otp_expired contact={contact} purpose={purpose} exp={exp_dt.isoformat()}")
            return jsonify({"ok": False, "error": "otp_expired"}), 401

        # mark used
        _sb().table(WEB_OTP_TABLE).update({"used": True}).eq("id", row["id"]).execute()

        account_id = _upsert_account_for_contact(contact)
        if not account_id:
            return jsonify({"ok": False, "error": "account_create_failed"}), 500

        raw_token = secrets.token_hex(32)
        expires_at = _now_utc() + timedelta(days=WEB_SESSION_TTL_DAYS)

        _sb().table(WEB_TOKEN_TABLE).insert(
            {
                "token_hash": _token_hash(raw_token),
                "account_id": account_id,
                "expires_at": expires_at.isoformat(),
                "revoked": False,
            }
        ).execute()

        _dbg(f"[web_auth] verify_otp ok account_id={account_id} token_hash_prefix={_token_hash(raw_token)[:12]}")

        return jsonify(
            {
                "ok": True,
                "token": raw_token,
                "account_id": account_id,
                "expires_at": expires_at.isoformat(),
            }
        )

    except Exception as e:
        _dbg(f"[web_auth] verify_exception: {type(e).__name__}: {str(e)[:200]}")
        _dbg("[web_auth] traceback:\n" + traceback.format_exc())
        return jsonify({"ok": False, "error": "verify_failed"}), 500


@bp.get("/me")
@bp.get("/web/auth/me")
@require_auth_plus
def me():
    account_id = g.account_id

    res = (
        _sb()
        .table("accounts")
        .select("*")
        .eq("id", account_id)  # your table uses `id` column
        .limit(1)
        .execute()
    )

    rows = res.data or []
    if not rows:
        return jsonify({"ok": False}), 404

    return jsonify({"ok": True, "account": rows[0]})
