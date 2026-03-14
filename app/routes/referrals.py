from __future__ import annotations

from typing import Any, Dict

from flask import Blueprint, jsonify, request

from app.services.referral_service import (
    compute_approved_payout_balance,
    ensure_referral_profile,
    get_referral_summary,
    list_payouts_for_account,
    list_referrals_for_referrer,
    list_rewards_for_account,
)
from app.services.web_auth_service import get_account_id_from_request

bp = Blueprint("referrals", __name__)


def _auth_account_id() -> tuple[str | None, Dict[str, Any]]:
    return get_account_id_from_request(request)


def _limit_arg(default: int = 50, minimum: int = 1, maximum: int = 500) -> int:
    raw = (request.args.get("limit") or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
        return max(minimum, min(value, maximum))
    except Exception:
        return default


@bp.get("/referrals/me")
def referral_me():
    account_id, debug = _auth_account_id()
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    profile = ensure_referral_profile(account_id)
    summary = get_referral_summary(account_id)
    payout_balance = compute_approved_payout_balance(account_id)

    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "profile": profile,
            "summary": summary,
            "approved_payout_balance": str(payout_balance),
            "debug": {"auth": debug},
        }
    ), 200


@bp.get("/referrals/history")
def referral_history():
    account_id, debug = _auth_account_id()
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    rows = list_referrals_for_referrer(account_id, limit=_limit_arg())
    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "count": len(rows),
            "rows": rows,
            "debug": {"auth": debug},
        }
    ), 200


@bp.get("/referrals/rewards")
def referral_rewards():
    account_id, debug = _auth_account_id()
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    rows = list_rewards_for_account(account_id, limit=_limit_arg())
    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "count": len(rows),
            "rows": rows,
            "debug": {"auth": debug},
        }
    ), 200


@bp.get("/referrals/payouts")
def referral_payouts():
    account_id, debug = _auth_account_id()
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    rows = list_payouts_for_account(account_id, limit=_limit_arg())
    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "count": len(rows),
            "rows": rows,
            "debug": {"auth": debug},
        }
    ), 200

