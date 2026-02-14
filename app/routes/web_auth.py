# app/routes/web_auth.py
from __future__ import annotations

from flask import Blueprint, jsonify, request
from ..core.config import ENV
from ..services.web_otp_service import (
    normalize_contact,
    can_resend,
    create_otp,
    verify_otp,
    dev_last_otp,
)
from ..services.accounts_web_link_service import get_or_create_account_for_web
from ..services.web_auth_tokens import issue_access_token

bp = Blueprint("web_auth", __name__)

@bp.post("/web/auth/start")
def web_auth_start():
    body = request.get_json(silent=True) or {}
    contact = normalize_contact(body.get("contact") or "")

    if not contact:
        return jsonify({"ok": False, "error": "Missing contact"}), 400

    # Basic guard: in your product, this should be phone_e164 like +234...
    if not contact.startswith("+") and "@" not in contact:
        return jsonify({"ok": False, "error": "Contact must be phone_e164 (+...) or email"}), 400

    if not can_resend(contact):
        return jsonify({"ok": False, "error": "Please wait a few seconds before requesting another OTP"}), 429

    # Ensure account exists early (so verify step is clean)
    account_id = get_or_create_account_for_web(contact)

    code, expires_at = create_otp(contact)

    resp = {
        "ok": True,
        "contact": contact,
        "expires_at": expires_at.isoformat(),
        "account_id": account_id if ENV.lower() != "prod" else None,  # DEV convenience
    }

    # DEV ONLY: return OTP to frontend so you spend $0 now
    if ENV.lower() != "prod":
        resp["dev_otp"] = code

    return jsonify(resp)

@bp.post("/web/auth/verify")
def web_auth_verify():
    body = request.get_json(silent=True) or {}
    contact = normalize_contact(body.get("contact") or "")
    code = (body.get("code") or "").strip()

    if not contact or not code:
        return jsonify({"ok": False, "error": "Missing contact or code"}), 400

    ok = verify_otp(contact, code)
    if not ok:
        return jsonify({"ok": False, "error": "Invalid or expired OTP"}), 401

    account_id = get_or_create_account_for_web(contact)
    token = issue_access_token({"account_id": account_id, "channel": "web"})

    return jsonify({
        "ok": True,
        "account_id": account_id,
        "access_token": token,
    })

@bp.get("/web/auth/dev_last_otp")
def web_auth_dev_last_otp():
    # optional helper to quickly fetch OTP in dev
    if ENV.lower() == "prod":
        return jsonify({"ok": False, "error": "Not allowed"}), 403

    contact = normalize_contact(request.args.get("contact") or "")
    if not contact:
        return jsonify({"ok": False, "error": "Missing contact"}), 400

    otp = dev_last_otp(contact)
    return jsonify({"ok": True, "contact": contact, "dev_otp": otp})
