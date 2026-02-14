# app/routes/web_auth.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.web_auth_service import (
    request_web_otp,
    verify_web_otp,
    require_web_session,
    logout_web_session,
)

bp = Blueprint("web_auth", __name__)


@bp.post("/web/auth/request-otp")
def web_request_otp():
    """
    Request OTP for Web login.
    Body:
      {
        "phone_e164": "+2348012345678",
        "device_id": "optional-string",
        "shared_secret": "optional-dev-secret"
      }

    DEV behavior:
      - Stores OTP in web_otps (hashed)
      - Returns otp in response ONLY if DEV OTP is enabled
    """
    body = request.get_json(silent=True) or {}
    phone_e164 = (body.get("phone_e164") or "").strip()
    device_id = (body.get("device_id") or "").strip() or None
    shared_secret = (body.get("shared_secret") or "").strip() or None

    if not phone_e164:
        return jsonify({"ok": False, "error": "phone_e164 is required"}), 400

    result = request_web_otp(phone_e164=phone_e164, device_id=device_id, shared_secret=shared_secret)
    status = 200 if result.get("ok") else 400
    return jsonify(result), status


@bp.post("/web/auth/verify-otp")
def web_verify_otp():
    """
    Verify OTP and create a web session.
    Body:
      {
        "phone_e164": "+2348012345678",
        "otp": "123456",
        "device_id": "optional-string"
      }

    Returns:
      {
        ok: true,
        session_token: "...",
        account_id: "...",
        expires_at: "..."
      }
    """
    body = request.get_json(silent=True) or {}
    phone_e164 = (body.get("phone_e164") or "").strip()
    otp = (body.get("otp") or "").strip()
    device_id = (body.get("device_id") or "").strip() or None

    if not phone_e164 or not otp:
        return jsonify({"ok": False, "error": "phone_e164 and otp are required"}), 400

    result = verify_web_otp(phone_e164=phone_e164, otp=otp, device_id=device_id)
    status = 200 if result.get("ok") else 401
    return jsonify(result), status


@bp.get("/web/auth/me")
def web_me():
    """
    Validate current session and return account info.
    Header: Authorization: Bearer <session_token>
    """
    auth = request.headers.get("Authorization") or ""
    result = require_web_session(auth_header=auth)
    status = 200 if result.get("ok") else 401
    return jsonify(result), status


@bp.post("/web/auth/logout")
def web_logout():
    """
    Logout: revoke current session token.
    Header: Authorization: Bearer <session_token>
    """
    auth = request.headers.get("Authorization") or ""
    result = logout_web_session(auth_header=auth)
    status = 200 if result.get("ok") else 401
    return jsonify(result), status
