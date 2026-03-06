# app/routes/web_auth.py
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request, make_response

from app.core.config import WEB_AUTH_COOKIE_NAME
from app.services.web_auth_service import (
    request_web_otp,
    verify_web_otp_and_issue_token,
    logout_web_session,
    get_account_id_from_request,
)
from app.services.mail_service import send_otp_email

bp = Blueprint("web_auth", __name__)


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _cookie_mode_enabled() -> bool:
    # Preferred env var
    v = _env("COOKIE_AUTH_ENABLED", "")
    if v:
        return _truthy(v)
    return True


def _cookie_secure() -> bool:
    v = _env("WEB_AUTH_COOKIE_SECURE", "")
    if v:
        return _truthy(v)
    return _truthy(_env("COOKIE_SECURE", "1"))


def _cookie_samesite() -> str:
    v = _env("WEB_AUTH_COOKIE_SAMESITE", "")
    if v:
        return v
    return _env("COOKIE_SAMESITE", "None")


def _cookie_domain() -> Optional[str]:
    v = _env("WEB_AUTH_COOKIE_DOMAIN", "")
    if v:
        return v or None
    d = _env("COOKIE_DOMAIN", "")
    return d or None


def _cookie_max_age() -> int:
    v = _env("WEB_AUTH_COOKIE_MAX_AGE", "")
    if v:
        return int(v or "2592000")
    return int(_env("COOKIE_MAX_AGE", "2592000") or "2592000")  # 30 days


def _return_bearer_in_json() -> bool:
    # If you still want token returned, set WEB_AUTH_RETURN_BEARER=1
    return _truthy(_env("WEB_AUTH_RETURN_BEARER", "0"))


def _dev_return_plain_otp() -> bool:
    # DEV ONLY (never enable in prod)
    return _truthy(_env("WEB_OTP_RETURN_PLAIN", "0"))


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

    if _dev_return_plain_otp() and otp_plain:
        out["otp"] = otp_plain

    resp = make_response(jsonify(out), 200)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.post("/web/auth/verify-otp")
def verify_otp():
    body = request.get_json(silent=True) or {}

    contact = (body.get("contact") or body.get("email") or "").strip().lower()
    otp = (body.get("otp") or body.get("code") or "").strip()
    purpose = (body.get("purpose") or "web_login").strip().lower()

    if not contact or not otp:
        return jsonify({"ok": False, "error": "contact_and_otp_required"}), 400

    # ✅ Pass ip/user_agent into session creation
    r = verify_web_otp_and_issue_token(
        contact=contact,
        otp=otp,
        purpose=purpose,
        ip=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
    )

    if not r.get("ok"):
        return jsonify(r), 400

    token = (r.get("token") or "").strip()

    # cookie-only mode: remove token from JSON unless explicitly requested
    if _cookie_mode_enabled() and not _return_bearer_in_json():
        r = {**r}
        r.pop("token", None)

    resp = make_response(jsonify(r), 200)
    resp.headers["Cache-Control"] = "no-store"

    # ✅ set cookie only if cookie mode enabled AND token exists
    if _cookie_mode_enabled() and token:
        secure = _cookie_secure()
        samesite = _cookie_samesite()

        if samesite.lower() == "none" and not secure:
            return jsonify(
                {
                    "ok": False,
                    "error": "cookie_config_invalid",
                    "message": "SameSite=None requires Secure cookies (WEB_AUTH_COOKIE_SECURE=1).",
                    "debug": {"WEB_AUTH_COOKIE_SAMESITE": samesite, "WEB_AUTH_COOKIE_SECURE": secure},
                }
            ), 500

        max_age = _cookie_max_age()
        domain = _cookie_domain()

        resp.set_cookie(
            WEB_AUTH_COOKIE_NAME,
            token,
            max_age=max_age,
            httponly=True,
            secure=secure,
            samesite=samesite,
            path="/",
            domain=domain,
        )

    return resp


@bp.get("/web/auth/me")
def me():
    account_id, debug = get_account_id_from_request(request)
    if not account_id:
        resp = make_response(jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    resp = make_response(jsonify({"ok": True, "account_id": account_id, "debug": debug}), 200)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.post("/web/auth/logout")
def logout():
    r = logout_web_session(request)

    resp = make_response(jsonify(r), 200)
    resp.headers["Cache-Control"] = "no-store"

    domain = _cookie_domain()
    resp.delete_cookie(WEB_AUTH_COOKIE_NAME, path="/", domain=domain)

    return resp
