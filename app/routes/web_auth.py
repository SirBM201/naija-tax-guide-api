# app/routes/web_auth.py
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Dict

from flask import Blueprint, jsonify, request, make_response

from app.services.web_auth_service import (
    request_web_otp,
    verify_web_otp_and_issue_token,
    logout_web_session,
    get_account_id_from_request,
    WEB_AUTH_COOKIE_NAME,
)

bp = Blueprint("web_auth", __name__)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _smtp_enabled() -> bool:
    return all(
        (os.getenv("SMTP_HOST"), os.getenv("SMTP_PORT"), os.getenv("SMTP_USER"), os.getenv("SMTP_PASS"), os.getenv("SMTP_FROM"))
    )


def _send_otp_email(to_email: str, otp: str) -> None:
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    pw = os.getenv("SMTP_PASS", "")
    from_email = os.getenv("SMTP_FROM", user)

    subject = os.getenv("WEB_OTP_EMAIL_SUBJECT", "Your Naija Tax Guide OTP")
    body = f"Your OTP code is: {otp}\n\nIt expires in a few minutes. If you did not request this, ignore this email."

    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls(context=ctx)
        server.login(user, pw)
        server.send_message(msg)


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

    # If SMTP configured, email it
    if otp_plain and _smtp_enabled():
        try:
            _send_otp_email(contact, otp_plain)
            delivery["sent"] = True
            delivery["provider"] = "smtp"
        except Exception as e:
            # Do NOT 500; return ok but show delivery error
            delivery["sent"] = False
            delivery["error"] = "email_send_failed"
            delivery["root_cause"] = repr(e)

    # If SMTP not configured, do NOT 500. Optionally return OTP in dev.
    if not delivery.get("sent") and not _smtp_enabled():
        delivery["sent"] = False
        delivery["error"] = "email_not_configured"
        delivery["fix"] = "Set SMTP_* env vars on backend OR set WEB_OTP_RETURN_PLAIN=1 for dev testing."

    out = {
        "ok": True,
        "contact": r.get("contact"),
        "purpose": r.get("purpose"),
        "expires_at": r.get("expires_at"),
        "delivery": delivery,
        "debug": r.get("debug", {}),
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
