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
    # Support schemas where PK may be account_id or id
    for pk in ("account_id", "id"):
        try:
            # Only query columns that exist (best effort)
            res = (
                _sb()
                .table("accounts")
                .select("*")
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


# Support BOTH endpoints (in case you registered blueprints differently)
@bp.get("/me")
@bp.get("/web/auth/me")
@require_auth_plus
def me():
    account_id = getattr(g, "account_id", None)
    if not account_id:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    acct = _get_account(str(account_id))
    if not acct:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    phone = (acct.get("phone") or acct.get("provider_user_id") or "").strip()

    # require_auth_plus (latest) sets:
    # g.raw_token_source and g.web_token_hash
    # Some earlier versions used different names, so we keep best-effort.
    source = getattr(g, "raw_token_source", None) or getattr(g, "auth_source", None)

    return (
        jsonify(
            {
                "ok": True,
                "account": {
                    "account_id": acct.get("account_id") or acct.get("id"),
                    "display_name": acct.get("display_name"),
                    "phone_e164": phone,
                    "provider": acct.get("provider"),
                    "provider_user_id": acct.get("provider_user_id"),
                    "created_at": acct.get("created_at"),
                },
                "auth": {
                    "source": source,
                },
                # keep these keys stable even if not yet wired
                "subscription": getattr(g, "subscription", {}) or {},
                "credits": getattr(g, "credits", {}) or {},
            }
        ),
        200,
    )


@bp.get("/billing/me")
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
