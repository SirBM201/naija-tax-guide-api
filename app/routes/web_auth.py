# app/routes/web_auth.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..core.config import WEB_DEV_RETURN_OTP
from ..services.accounts_service import upsert_account
from ..services.web_otp_service import create_otp, verify_otp, otp_request_cooldown_ok
from ..services.web_sessions_service import (
    create_web_session,
    validate_web_session,
    touch_session_best_effort,
    revoke_session,
)

bp = Blueprint("web_auth", __name__)


def _get_ip() -> str | None:
    # if behind proxy, you may later trust X-Forwarded-For in a controlled way
    return request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr


def _get_ua() -> str | None:
    return request.headers.get("User-Agent")


def _bearer_token() -> str | None:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth:
        return None
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip() or None
    return None


@bp.post("/web/auth/request-otp")
def request_otp():
    """
    Body:
      { "phone_e164": "+234..." }  OR  { "contact": "+234..." }
    Returns:
      { ok, expires_at, otp? }  (otp only in DEV)
    """
    body = request.get_json(silent=True) or {}
    contact = (body.get("phone_e164") or body.get("contact") or "").strip()

    if not contact:
        return jsonify({"ok": False, "error": "phone_e164 is required"}), 400

    # basic sanity for phone-ish input (you can tighten later)
    if len(contact) < 7:
        return jsonify({"ok": False, "error": "invalid phone"}), 400

    if not otp_request_cooldown_ok(contact, "web_login"):
        return jsonify({"ok": False, "error": "too_many_requests"}), 429

    otp = create_otp(contact=contact, purpose="web_login")
    resp = {"ok": True, "expires_at": otp["expires_at"]}

    if WEB_DEV_RETURN_OTP:
        resp["otp"] = otp["code_plain"]

    return jsonify(resp)


@bp.post("/web/auth/verify-otp")
def verify_otp_route():
    """
    Body:
      { "phone_e164": "+234...", "otp": "123456" }
    Returns:
      { ok, token, account_id, expires_at }
    """
    body = request.get_json(silent=True) or {}
    contact = (body.get("phone_e164") or body.get("contact") or "").strip()
    code = (body.get("otp") or body.get("code") or "").strip()

    if not contact or not code:
        return jsonify({"ok": False, "error": "phone_e164 and otp are required"}), 400

    ok, reason = verify_otp(contact=contact, code_plain=code, purpose="web_login")
    if not ok:
        return jsonify({"ok": False, "error": reason}), 401

    # Create/Find account identity for web channel
    # provider="web", provider_user_id=phone_e164 (simple + stable)
    account_id, _created = upsert_account(
        provider="web",
        provider_user_id=contact,
        display_name=None,
        phone=contact,
        phone_e164=contact,
    )

    sess = create_web_session(
        account_id=account_id,
        ip=_get_ip(),
        user_agent=_get_ua(),
    )

    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "token": sess["token"],
            "expires_at": sess["expires_at"],
        }
    )


@bp.get("/web/auth/me")
def me():
    """
    Header: Authorization: Bearer <token>
    Returns:
      { ok, account_id }
    """
    token = _bearer_token()
    if not token:
        return jsonify({"ok": False, "error": "missing_token"}), 401

    ok, account_id, reason = validate_web_session(token)
    if not ok:
        return jsonify({"ok": False, "error": reason}), 401

    touch_session_best_effort(token)
    return jsonify({"ok": True, "account_id": account_id})


@bp.post("/web/auth/logout")
def logout():
    """
    Header: Authorization: Bearer <token>
    """
    token = _bearer_token()
    if not token:
        return jsonify({"ok": False, "error": "missing_token"}), 401

    revoked = revoke_session(token)
    return jsonify({"ok": True, "revoked": revoked})
