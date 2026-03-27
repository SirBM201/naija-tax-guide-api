from __future__ import annotations

import os

from flask import Blueprint, jsonify, request

from app.services.guest_access_service import (
    VISITOR_TOKEN_COOKIE_NAME,
    attach_guest_session_to_account,
    ensure_guest_session,
)
from app.services.web_auth_service import get_account_id_from_request

bp = Blueprint("entry", __name__)

COOKIE_MAX_AGE = int(os.getenv("VISITOR_TOKEN_COOKIE_MAX_AGE", "31536000"))


@bp.get("/entry/bootstrap")
def entry_bootstrap():
    session, visitor_token, _ = ensure_guest_session(request)

    response = jsonify(
        {
            "ok": True,
            "guest_session": {
                "guest_session_id": session.get("guest_session_id"),
                "entry_channel": session.get("entry_channel"),
                "referral_code": session.get("referral_code"),
                "referrer_account_id": session.get("referrer_account_id"),
                "referral_locked": bool(session.get("referral_locked")),
                "first_seen_at": session.get("first_seen_at"),
                "last_seen_at": session.get("last_seen_at"),
            },
            "visitor_token_present": True,
        }
    )
    response.set_cookie(
        VISITOR_TOKEN_COOKIE_NAME,
        visitor_token,
        max_age=COOKIE_MAX_AGE,
        httponly=False,
        secure=True,
        samesite="Lax",
        path="/",
    )
    return response


@bp.post("/entry/link-account")
def entry_link_account():
    account_id, _meta = get_account_id_from_request(request)
    if not account_id:
        return jsonify({"ok": False, "error": "authentication_required"}), 401

    visitor_token = (request.cookies.get(VISITOR_TOKEN_COOKIE_NAME) or "").strip()
    if not visitor_token:
        return jsonify({"ok": False, "error": "visitor_token_missing"}), 400

    result = attach_guest_session_to_account(
        visitor_token=visitor_token,
        account_id=account_id,
    )
    code = 200 if result.get("ok") else 400
    return jsonify(result), code
