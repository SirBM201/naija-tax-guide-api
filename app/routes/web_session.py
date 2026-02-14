# app/routes/web_session.py
from __future__ import annotations

from typing import Any, Dict, Optional
from flask import Blueprint, jsonify, g

from app.core.auth import require_auth_plus
from app.core.supabase_client import supabase
from app.services.web_tokens_service import revoke_token

bp = Blueprint("web_session", __name__)


def _get_account(account_id: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            supabase.table("accounts")
            .select("account_id, provider, provider_user_id, display_name, phone, created_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        return rows[0] if rows else None
    except Exception:
        return None


# Support BOTH endpoints (in case you registered blueprints differently)
@bp.get("/me")
@bp.get("/web/auth/me")
@require_auth_plus  # works as @require_auth_plus or @require_auth_plus()
def me():
    account_id = getattr(g, "account_id", None)
    token_row = getattr(g, "token_row", {}) or {}
    sub = getattr(g, "subscription", {}) or {}
    credits = getattr(g, "credits", {}) or {}

    if not account_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    acct = _get_account(account_id)
    if not acct:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    phone = (acct.get("phone") or acct.get("provider_user_id") or "").strip()

    return jsonify(
        {
            "ok": True,
            "account": {
                "account_id": acct.get("account_id"),
                "display_name": acct.get("display_name"),
                "phone_e164": phone,
                "provider": acct.get("provider"),
                "provider_user_id": acct.get("provider_user_id"),
                "created_at": acct.get("created_at"),
            },
            "auth": {"token_expires_at": token_row.get("expires_at")},
            "subscription": sub,
            "credits": credits,
        }
    ), 200


@bp.get("/billing/me")
@require_auth_plus
def billing_me():
    return jsonify(
        {
            "ok": True,
            "subscription": getattr(g, "subscription", {}) or {},
            "credits": getattr(g, "credits", {}) or {},
        }
    ), 200


@bp.post("/web/auth/logout")
@require_auth_plus
def logout():
    token = getattr(g, "auth_token", "") or ""
    ok, err = revoke_token(token)
    if not ok:
        return jsonify({"ok": False, "error": err or "Failed to logout"}), 500
    return jsonify({"ok": True}), 200
