# app/routes/web_auth.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..core.config import ENV
from ..services.web_otp_service import request_web_login_otp, verify_web_login_otp
from ..services.web_sessions_service import validate_web_session, touch_session_best_effort

bp = Blueprint("web_auth", __name__)

@bp.post("/web/auth/request-otp")
def web_request_otp():
    data = request.get_json(silent=True) or {}
    contact = (data.get("contact") or "").strip()
    purpose = (data.get("purpose") or "web_login").strip()

    if not contact:
        return jsonify({"ok": False, "error": "missing_contact"}), 400

    # This generates + stores OTP (hash) in DB; in DEV it can return plain OTP for local testing
    result = request_web_login_otp(contact=contact, purpose=purpose)

    # IMPORTANT: Only return dev_otp in non-prod
    if (ENV or "").lower() != "prod":
        return jsonify(
            {
                "ok": True,
                "contact": contact,
                "purpose": purpose,
                "dev_otp": result.get("dev_otp"),  # <--- shown only in DEV
            }
        )

    return jsonify({"ok": True, "contact": contact, "purpose": purpose})


@bp.post("/web/auth/verify-otp")
def web_verify_otp():
    data = request.get_json(silent=True) or {}
    contact = (data.get("contact") or "").strip()
    otp = (data.get("otp") or "").strip()
    purpose = (data.get("purpose") or "web_login").strip()

    if not contact or not otp:
        return jsonify({"ok": False, "error": "missing_contact_or_otp"}), 400

    # returns token if ok
    res = verify_web_login_otp(contact=contact, otp=otp, purpose=purpose)
    if not res.get("ok"):
        return jsonify(res), 401

    return jsonify(res)


@bp.get("/web/auth/me")
def web_me():
    auth = (request.headers.get("Authorization") or "").strip()
    token = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    if not token:
        return jsonify({"ok": False, "error": "missing_token"}), 401

    ok, account_id, reason = validate_web_session(token)
    if not ok or not account_id:
        return jsonify({"ok": False, "error": reason}), 401

    touch_session_best_effort(token)

    return jsonify({"ok": True, "account_id": account_id})
