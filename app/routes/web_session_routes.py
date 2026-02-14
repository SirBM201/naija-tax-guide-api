# app/routes/web_session_routes.py
from __future__ import annotations

from typing import Any, Dict, Optional
from flask import Blueprint, jsonify, g, request

from ..core.auth import require_auth
from ..core.supabase_client import supabase
from ..services.web_tokens_service import revoke_token


bp = Blueprint("web_session", __name__)


def _get_account(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Expects an 'accounts' table.
    We return safe public fields only.
    """
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


@bp.get("/me")
@require_auth
def me():
    """
    Protected endpoint for frontend bootstrapping.
    Requires Bearer token.
    """
    account_id = getattr(g, "account_id", None)
    token_row = getattr(g, "token_row", {}) or {}

    if not account_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    acct = _get_account(account_id)
    if not acct:
        # Token valid but account missing -> still unauthorized in practice
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    # Normalize the phone field for web UI friendliness
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
            "auth": {
                "token_expires_at": token_row.get("expires_at"),
            },
        }
    ), 200


@bp.post("/web/auth/logout")
@require_auth
def logout():
    """
    Logout (revoke current token).
    Idempotent: returns ok even if token doesn't exist anymore.
    """
    token = getattr(g, "auth_token", None) or ""
    ok, err = revoke_token(token)
    if not ok:
        return jsonify({"ok": False, "error": err or "Failed to logout"}), 500
    return jsonify({"ok": True}), 200
