# app/routes/web_auth.py
from __future__ import annotations

import os
from typing import Any, Dict

from flask import Blueprint, jsonify, request, make_response

from app.services.web_auth_service import (
    request_web_otp,
    verify_web_otp_and_issue_token,
    logout_web_session,
    get_account_id_from_request,
    WEB_AUTH_COOKIE_NAME,
)
from app.services.mail_service import send_otp_email

bp = Blueprint("web_auth", __name__)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


@bp.post("/web/auth/request-otp")
def request_otp():
    body = request.get_json(silent=True) or {}

    contact = (body.get("contact") or body.get("email") or "").strip().lower()
    purpose = (body.get("purpose") or "web_login").strip().lower()
    device_id = (body.get("device_id") or "").strip()

    if not contact:
        return jsonify({"ok": False, "error": "contact_required"}), 400

    r = request_web_otp(
        contact=contact,
        purpose=purpose,
        device_id=device_id or None,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )

    if not r.get("ok"):
        return jsonify(r), 400

    otp_plain = r.get("_otp_plain")  # server-only
    dev_return_plain = _truthy(os.getenv("WEB_OTP_RETURN_PLAIN", "0"))

    delivery: Dict[str, Any] = {"mode": "email", "sent": False}

    if otp_plain:
        mail_res = send_otp_email(contact, otp_plain)
        if mail_res.get("ok"):
            delivery["sent"] = True
            delivery["provider"] = "smtp"
        else:
            delivery["sent"] = False
            delivery["error"] = mail_res.get("error") or "email_send_failed"
            delivery["root_cause"] = mail_res.get("root_cause")
            delivery["debug"] = mail_res.get("debug")

    out = {
        "ok": True,
        "contact": r.get("contact"),
        "purpose": r.get("purpose"),
        "expires_at": r.get("expires_at"),
        "delivery": delivery,
        "debug": r.get("debug", {}),
    }

    # DEV ONLY (never enable in prod)
    if dev_return_plain and otp_plain:
        out["otp"] = otp_plain

    return jsonify(out), 200


@bp.post("/web/auth/verify-otp")
def verify_otp():
    body = request.get_json(silent=True) or {}

    contact = (body.get("contact") or body.get("email") or "").strip().lower()
    otp = (body.get("otp") or body.get("code") or "").strip()
    purpose = (body.get("purpose") or "web_login").strip().lower()

    if not contact or not otp:
        return jsonify({"ok": False, "error": "contact_and_otp_required"}), 400

    r = verify_web_otp_and_issue_token(contact=contact, otp=otp, purpose=purpose)
    if not r.get("ok"):
        return jsonify(r), 400

    token = r["token"]
    resp = make_response(jsonify(r), 200)

    if _truthy(os.getenv("COOKIE_AUTH_ENABLED", "1")):
        secure = _truthy(os.getenv("COOKIE_SECURE", "1"))
        samesite = (os.getenv("COOKIE_SAMESITE", "None") or "None").strip()
        max_age = int(os.getenv("COOKIE_MAX_AGE", "2592000") or "2592000")

        resp.set_cookie(
            WEB_AUTH_COOKIE_NAME,
            token,
            max_age=max_age,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path="/",
        )

    return resp


@bp.get("/web/auth/me")
def me():
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401
    return jsonify({"ok": True, "account_id": account_id, "debug": debug}), 200


@bp.post("/web/auth/logout")
def logout():
    r = logout_web_session(request)
    resp = make_response(jsonify(r), 200)
    resp.delete_cookie(WEB_AUTH_COOKIE_NAME, path="/")
    return resp
