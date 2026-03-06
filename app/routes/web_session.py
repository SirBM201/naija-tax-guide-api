# app/routes/web_session.py
from __future__ import annotations

from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, g

from app.core.auth import require_auth_plus
from app.core.supabase_client import supabase

bp = Blueprint("web_session", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _get_account(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Canonical identity is accounts.account_id.
    We still try id for backward compatibility.
    """
    for pk in ("account_id", "id"):
        try:
            res = (
                _sb()
                .table("accounts")
                .select("id,account_id,display_name,phone,provider,provider_user_id,created_at,email")
                .eq(pk, account_id)
                .limit(1)
                .execute()
            )
            rows = (res.data or []) if hasattr(res, "data") else []
            if rows:
                return rows[0]
        except Exception:
            continue
    return None


@bp.get("/web/session/me")
@require_auth_plus
def me():
    account_id = getattr(g, "account_id", None)
    if not account_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    acct = _get_account(str(account_id))
    if not acct:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    # if phone is empty, fallback to provider_user_id
    phone = (acct.get("phone") or acct.get("provider_user_id") or "").strip()

    source = getattr(g, "raw_token_source", None) or getattr(g, "auth_source", None)

    return (
        jsonify(
            {
                "ok": True,
                "account": {
                    "account_id": acct.get("account_id") or acct.get("id"),
                    "display_name": acct.get("display_name"),
                    "email": acct.get("email"),
                    "phone_e164": phone,
                    "provider": acct.get("provider"),
                    "provider_user_id": acct.get("provider_user_id"),
                    "created_at": acct.get("created_at"),
                },
                "auth": {
                    "source": source,
                    "token_expires_at": (getattr(g, "token_row", {}) or {}).get("expires_at"),
                },
                "subscription": getattr(g, "subscription", {}) or {},
                "credits": getattr(g, "credits", {}) or {},
            }
        ),
        200,
    )


@bp.get("/web/session/billing/me")
@require_auth_plus
def billing_me():
    return (
        jsonify(
            {
                "ok": True,
                "subscription": getattr(g, "subscription", {}) or {},
                "credits": getattr(g, "credits", {}) or {},
            }
        ),
        200,
    )
