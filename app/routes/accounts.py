from __future__ import annotations

from flask import Blueprint, jsonify, request

# SAFE import: avoids "cannot import name ..." boot crash
from app.services import accounts_service as acct

bp = Blueprint("accounts", __name__)


def _bad(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status


@bp.post("/accounts")
def create_or_get_account():
    """
    Create or update an account shell (pre-link).
    Body:
      {
        "provider": "wa" | "tg" | "msgr" | "ig" | "email" | "web",
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

    if not hasattr(acct, "upsert_account"):
        return _bad("Server misconfigured: upsert_account missing", 500)

    res = acct.upsert_account(
        provider=provider,
        provider_user_id=provider_user_id,
        display_name=display_name,
        phone=phone,
    )
    if not res.get("ok"):
        return _bad(res.get("error") or "Failed")

    account = res.get("account") or {}
    return jsonify({"ok": True, "account": account, "account_id": account.get("id")})


@bp.get("/accounts/lookup")
def account_lookup_get():
    """
    GET /api/accounts/lookup?provider=wa&provider_user_id=234...
    Returns auth mapping if linked + plan_status.
    """
    provider = (request.args.get("provider") or "").strip().lower()
    provider_user_id = (request.args.get("provider_user_id") or "").strip()

    if not hasattr(acct, "lookup_account"):
        return _bad("Server misconfigured: lookup_account missing", 500)

    res = acct.lookup_account(provider=provider, provider_user_id=provider_user_id)
    if not res.get("ok"):
        return _bad(res.get("error") or "Lookup failed")

    auth_user_id = res.get("auth_user_id")
    if auth_user_id and hasattr(acct, "get_plan_status"):
        plan_status = acct.get_plan_status(auth_user_id)
    else:
        plan_status = {"ok": True, "known": False, "is_active": False, "plan": None, "status": None, "plan_expiry": None}

    return jsonify(
        {
            "ok": True,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "found": res.get("found", False),
            "linked": res.get("linked", False),
            "auth_user_id": auth_user_id,
            "account": res.get("account"),
            "account_id": (res.get("account") or {}).get("id"),
            "plan_status": plan_status,
        }
    )


@bp.post("/accounts/lookup")
def account_lookup_post():
    """
    POST /api/accounts/lookup
    Body:
      {
        "provider": "wa" | "tg" | "msgr" | "ig" | "email" | "web",
        "provider_user_id": "<string>"
      }
    Returns auth mapping if linked + plan_status.
    """
    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if not hasattr(acct, "lookup_account"):
        return _bad("Server misconfigured: lookup_account missing", 500)

    res = acct.lookup_account(provider=provider, provider_user_id=provider_user_id)
    if not res.get("ok"):
        return _bad(res.get("error") or "Lookup failed")

    auth_user_id = res.get("auth_user_id")
    if auth_user_id and hasattr(acct, "get_plan_status"):
        plan_status = acct.get_plan_status(auth_user_id)
    else:
        plan_status = {"ok": True, "known": False, "is_active": False, "plan": None, "status": None, "plan_expiry": None}

    return jsonify(
        {
            "ok": True,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "found": res.get("found", False),
            "linked": res.get("linked", False),
            "auth_user_id": auth_user_id,
            "account": res.get("account"),
            "account_id": (res.get("account") or {}).get("id"),
            "plan_status": plan_status,
        }
    )
