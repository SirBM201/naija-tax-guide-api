# app/routes/email_link.py
from __future__ import annotations

import os
import re
from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase
from app.services.accounts_service import upsert_account_link

bp = Blueprint("email_link", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _bad(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status


@bp.post("/email/link")
def link_email_with_code():
    """
    POST /api/email/link
    Body:
      { "email": "user@email.com", "code": "ABC23456" }
    """
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    code = (body.get("code") or "").strip().upper()

    if not email or not EMAIL_RE.match(email):
        return _bad("Valid email required")
    if not code:
        return _bad("Code required")

    # consume token
    try:
        res = supabase().rpc(
            "consume_link_token",
            {"p_provider": "email", "p_code": code, "p_provider_user_id": email},
        ).execute()
    except Exception as e:
        return _bad(f"RPC error: {str(e)}", 500)

    row = (res.data or [None])[0]
    if not row or not row.get("ok"):
        return _bad("Invalid or expired code", 400)

    auth_user_id = row.get("auth_user_id")
    if not auth_user_id:
        return _bad("consume_link_token returned no auth_user_id", 500)

    link = upsert_account_link(
        provider="email",
        provider_user_id=email,
        auth_user_id=auth_user_id,
        display_name=None,
        phone=None,
    )
    if not link.get("ok"):
        return jsonify({"ok": False, "error": link.get("error"), "reason": link.get("reason")}), 409

    return jsonify({"ok": True, "linked": True, "account": link.get("account")})
