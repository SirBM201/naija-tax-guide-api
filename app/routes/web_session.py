# app/routes/web_session.py
from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Blueprint, jsonify

from app.core.auth import require_auth_plus, get_auth, get_auth_plus
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


def _build_me_payload(account_id: str) -> Dict[str, Any]:
    acct = _get_account(account_id)
    if not acct:
        return {"ok": False, "error": "Unauthorized"}

    phone = (acct.get("phone") or acct.get("provider_user_id") or "").strip()

    auth_plus = get_auth_plus() or {}
    sub = auth_plus.get("subscription") or {}
    credits = auth_plus.get("credits") or {}

    return {
        "ok": True,
        "account": {
            "account_id": acct.get("account_id"),
            "display_name": acct.get("display_name"),
            "phone_e164": phone,
            "provider": acct.get("provider"),
            "provider_user_id": acct.get("provider_user_id"),
            "created_at": acct.get("created_at"),
        },
        # We don't expose token hash / raw token details here.
        "subscription": sub,
        "credits": credits,
    }


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------

@bp.get("/me")
@require_auth_plus
def me():
    auth = get_auth() or {}
    account_id = (auth.get("account_id") or "").strip()
    if not account_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    payload = _build_me_payload(account_id)
    if not payload.get("ok"):
        return jsonify(payload), 401
    return jsonify(payload), 200


# Alias to match your /api/_routes output
@bp.get("/web/auth/me")
@require_auth_plus
def web_auth_me():
    return me()


@bp.post("/web/auth/logout")
@require_auth_plus
def logout():
    auth = get_auth() or {}
    token = (auth.get("token") or "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    ok, err = revoke_token(token)
    if not ok:
        return jsonify({"ok": False, "error": err or "Failed to logout"}), 500
    return jsonify({"ok": True}), 200


@bp.get("/billing/me")
@require_auth_plus
def billing_me():
    """
    Convenience endpoint for frontend:
      returns only subscription + credits
    """
    auth_plus = get_auth_plus() or {}
    return jsonify(
        {
            "ok": True,
            "subscription": auth_plus.get("subscription") or {},
            "credits": auth_plus.get("credits") or {},
        }
    ), 200
