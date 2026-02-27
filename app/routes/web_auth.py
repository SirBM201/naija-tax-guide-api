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


def _mail_config_present() -> bool:
    """
    Mail sending is controlled by mail_service.py.
    Here we only do a light check so we can give a helpful response.
    """
    enabled = _truthy(os.getenv("MAIL_ENABLED")) or _truthy(os.getenv("SMTP_ENABLED"))
    if not enabled:
        return False

    # Prefer MAIL_* but also accept SMTP_* to avoid mismatch confusion.
    host = (os.getenv("MAIL_HOST") or os.getenv("SMTP_HOST") or "").strip()
    port = (os.getenv("MAIL_PORT") or os.getenv("SMTP_PORT") or "").strip()
    user = (os.getenv("MAIL_USER") or os.getenv("SMTP_USER") or "").strip()
    pw = (os.getenv("MAIL_PASS") or os.getenv("SMTP_PASS") or "").strip()

    # From can be MAIL_FROM_EMAIL or SMTP_FROM or fallback to user
    from_email = (os.getenv("MAIL_FROM_EMAIL") or os.getenv("SMTP_FROM") or user).strip()

    return bool(host and port and user and pw and from_email)


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
    dev_return_plain = _truthy(os.getenv("WEB_OTP_RETURN_PLAIN"))

    delivery: Dict[str, Any] = {"mode": "email", "sent": False}

    # Try to email OTP using the centralized mail_service
    if otp_plain and _mail_config_present():
        try:
            sent = bool(send_otp_email(to_email=contact, otp_code=otp_plain))
            delivery["sent"] = sent
            delivery["provider"] = "mail_service"
            if not sent:
                delivery["error"] = "email_send_failed"
                delivery["fix"] = "Check backend logs for [mail] ERROR and confirm MAIL_* or SMTP_* env vars."
        except Exception as e:
            delivery["sent"] = False
            delivery["error"] = "email_send_failed"
            delivery["root_cause"] = repr(e)
            delivery["fix"] = "Check backend logs and SMTP credentials (Mailtrap username/password/host/port)."

    # If mail config not present, do NOT 500. Optionally return OTP in dev.
    if not delivery.get("sent") and not _mail_config_present():
        delivery["sent"] = False
        delivery["error"] = "email_not_configured"
        delivery["fix"] = (
            "Set MAIL_ENABLED=true and MAIL_HOST/MAIL_PORT/MAIL_USER/MAIL_PASS/MAIL_FROM_EMAIL "
            "(or SMTP_* equivalents), OR set WEB_OTP_RETURN_PLAIN=1 for dev testing."
        )

    out = {
        "ok": True,
        "contact": r.get("contact"),
        "purpose": r.get("purpose"),
        "expires_at": r.get("expires_at"),
        "delivery": delivery,
        "debug": r.get("debug", {}),
        "debug_mail": {
            "mail_enabled": _truthy(os.getenv("MAIL_ENABLED")),
            "smtp_enabled": _truthy(os.getenv("SMTP_ENABLED")),
            "mail_config_present": _mail_config_present(),
            "has_MAIL_HOST": bool((os.getenv("MAIL_HOST") or "").strip()),
            "has_SMTP_HOST": bool((os.getenv("SMTP_HOST") or "").strip()),
        },
    }

    if dev_return_plain and otp_plain:
        out["otp"] = otp_plain  # DEV ONLY

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

    # cookie is optional: only enable if you want cookie auth
    if _truthy(os.getenv("COOKIE_AUTH_ENABLED", "1")):
        secure = _truthy(os.getenv("COOKIE_SECURE", "1"))
        samesite = os.getenv("COOKIE_SAMESITE", "None")
        max_age = int(os.getenv("COOKIE_MAX_AGE", "2592000"))

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
