# app/routes/web_auth.py
from __future__ import annotations

from typing import Any, Dict

from flask import Blueprint, jsonify, request, g

from app.core.auth import require_auth_plus
from app.core.config import WEB_AUTH_ENABLED
from app.core.supabase_client import supabase

from app.services.web_otp_service import (
    request_web_login_otp,
    verify_web_login_otp,
)

bp = Blueprint("web_auth", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _client_ip() -> str:
    """
    Best effort IP capture behind proxies:
    - X-Forwarded-For may contain: client, proxy1, proxy2...
    """
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return (request.headers.get("X-Real-IP") or request.remote_addr or "").strip()


def _normalize_payload() -> Dict[str, Any]:
    return request.get_json(silent=True) or {}


@bp.post("/request-otp")
@bp.post("/web/auth/request-otp")
def request_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled"}), 403

    data = _normalize_payload()
    contact = str(data.get("contact") or "").strip()
    purpose = str(data.get("purpose") or "web_login").strip() or "web_login"
    email_to = str(data.get("email") or "").strip().lower()

    result = request_web_login_otp(
        contact=contact,
        purpose=purpose,
        request_ip=_client_ip(),
        email_to=email_to,
    )

    # Map errors to HTTP status
    if not result.get("ok"):
        err = result.get("error")
        if err in {"missing_contact"}:
            return jsonify(result), 400
        if err in {"locked", "rate_limited"}:
            return jsonify(result), 429
        if err == "web_auth_disabled":
            return jsonify(result), 403
        return jsonify(result), 400

    return jsonify(result)


@bp.post("/verify-otp")
@bp.post("/web/auth/verify-otp")
def verify_otp():
    if not WEB_AUTH_ENABLED:
        return jsonify({"ok": False, "error": "web_auth_disabled"}), 403

    data = _normalize_payload()
    contact = str(data.get("contact") or "").strip()
    purpose = str(data.get("purpose") or "web_login").strip() or "web_login"
    otp = str(data.get("otp") or "").strip()

    result = verify_web_login_otp(
        contact=contact,
        otp=otp,
        purpose=purpose,
        request_ip=_client_ip(),
    )

    if not result.get("ok"):
        err = result.get("error")
        if err in {"missing_contact_or_otp"}:
            return jsonify(result), 400
        if err in {"locked"}:
            return jsonify(result), 429
        if err in {"invalid_otp"}:
            return jsonify(result), 401
        return jsonify(result), 400

    return jsonify(result)


@bp.get("/me")
@bp.get("/web/auth/me")
@require_auth_plus
def me():
    account_id = g.account_id

    res = (
        _sb()
        .table("accounts")
        .select("*")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )

    rows = res.data or []
    if not rows:
        return jsonify({"ok": False, "error": "not_found"}), 404

    return jsonify({"ok": True, "account": rows[0]})
