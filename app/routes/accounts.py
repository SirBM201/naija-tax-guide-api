# app/routes/accounts.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.accounts_service import upsert_account, lookup_account, get_plan_status

bp = Blueprint("accounts", __name__)


def _bad(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status


@bp.post("/accounts")
def create_or_get_account():
    """
    Create or update an account shell (pre-link).
    Body:
      {
        "provider": "wa" | "tg",
        "provider_user_id": "<string>",
        "display_name": "<optional>",
        "phone": "<optional>"
      }
    """
    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()
    display_name = (body.get("display_name") or "").strip() or None
    phone = (body.get("phone") or "").strip() or None

    res = upsert_account(
        provider=provider,
        provider_user_id=provider_user_id,
        display_name=display_name,
        phone=phone,
    )
    if not res.get("ok"):
        return _bad(res.get("error") or "Failed")

    return jsonify({"ok": True, "account": res.get("account")})


@bp.get("/accounts/lookup")
def account_lookup_get():
    """
    GET /api/accounts/lookup?provider=wa&provider_user_id=234...
    Returns auth mapping if linked + plan status.
    """
    provider = (request.args.get("provider") or "").strip().lower()
    provider_user_id = (request.args.get("provider_user_id") or "").strip()

    res = lookup_account(provider=provider, provider_user_id=provider_user_id)
    if not res.get("ok"):
        return _bad(res.get("error") or "Lookup failed")

    auth_user_id = res.get("auth_user_id")
    plan_status = get_plan_status(auth_user_id) if auth_user_id else {"ok": True, "known": False, "is_active": False}

    return jsonify(
        {
            "ok": True,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "found": res.get("found", False),
            "linked": res.get("linked", False),
            "auth_user_id": auth_user_id,
            "account": res.get("account"),
            "plan_status": plan_status,
        }
    )


@bp.post("/accounts/lookup")
def account_lookup_post():
    """
    POST /api/accounts/lookup
    Body:
      {
        "provider": "wa" | "tg",
        "provider_user_id": "<string>"
      }
    Returns auth mapping if linked + plan status.
    """
    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    res = lookup_account(provider=provider, provider_user_id=provider_user_id)
    if not res.get("ok"):
        return _bad(res.get("error") or "Lookup failed")

    auth_user_id = res.get("auth_user_id")
    plan_status = get_plan_status(auth_user_id) if auth_user_id else {"ok": True, "known": False, "is_active": False}

    return jsonify(
        {
            "ok": True,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "found": res.get("found", False),
            "linked": res.get("linked", False),
            "auth_user_id": auth_user_id,
            "account": res.get("account"),
            "plan_status": plan_status,
        }
    )
