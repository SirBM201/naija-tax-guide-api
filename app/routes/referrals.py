from __future__ import annotations

import logging
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
logger = logging.getLogger(__name__)
ROUTE_VERSION = "referrals_route_v2_safe"


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

    try:
        profile = ensure_referral_profile(account_id)
        summary = get_referral_summary(account_id)
        payout_balance = compute_approved_payout_balance(account_id)

        return jsonify(
            {
                "ok": True,
                "route_version": ROUTE_VERSION,
                "account_id": account_id,
                "profile": profile,
                "summary": summary,
                "approved_payout_balance": str(payout_balance),
                "debug": {"auth": debug},
            }
        ), 200
    except Exception as e:
        logger.exception("[%s] referral_me failed account_id=%s", ROUTE_VERSION, account_id)
        return jsonify(
            {
                "ok": False,
                "route_version": ROUTE_VERSION,
                "error": "referral_me_failed",
                "root_cause": repr(e),
                "fix": "Check referral_profiles table structure and ensure_referral_profile/get_referral_summary logic.",
                "account_id": account_id,
                "debug": {"auth": debug},
            }
        ), 500


@bp.get("/referrals/history")
def referral_history():
    account_id, debug = _auth_account_id()
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    try:
        rows = list_referrals_for_referrer(account_id, limit=_limit_arg())
        return jsonify(
            {
                "ok": True,
                "route_version": ROUTE_VERSION,
                "account_id": account_id,
                "count": len(rows),
                "rows": rows,
                "debug": {"auth": debug},
            }
        ), 200
    except Exception as e:
        logger.exception("[%s] referral_history failed account_id=%s", ROUTE_VERSION, account_id)
        return jsonify(
            {
                "ok": False,
                "route_version": ROUTE_VERSION,
                "error": "referral_history_failed",
                "root_cause": repr(e),
                "fix": "Check referrals table structure and list_referrals_for_referrer logic.",
                "account_id": account_id,
                "debug": {"auth": debug},
            }
        ), 500


@bp.get("/referrals/rewards")
def referral_rewards():
    account_id, debug = _auth_account_id()
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    try:
        rows = list_rewards_for_account(account_id, limit=_limit_arg())
        return jsonify(
            {
                "ok": True,
                "route_version": ROUTE_VERSION,
                "account_id": account_id,
                "count": len(rows),
                "rows": rows,
                "debug": {"auth": debug},
            }
        ), 200
    except Exception as e:
        logger.exception("[%s] referral_rewards failed account_id=%s", ROUTE_VERSION, account_id)
        return jsonify(
            {
                "ok": False,
                "route_version": ROUTE_VERSION,
                "error": "referral_rewards_failed",
                "root_cause": repr(e),
                "fix": "Check referral_rewards table structure and list_rewards_for_account logic.",
                "account_id": account_id,
                "debug": {"auth": debug},
            }
        ), 500


@bp.get("/referrals/payouts")
def referral_payouts():
    account_id, debug = _auth_account_id()
    if not account_id:
        return jsonify({"ok": False, "error": "unauthorized", "debug": debug}), 401

    try:
        rows = list_payouts_for_account(account_id, limit=_limit_arg())
        return jsonify(
            {
                "ok": True,
                "route_version": ROUTE_VERSION,
                "account_id": account_id,
                "count": len(rows),
                "rows": rows,
                "debug": {"auth": debug},
            }
        ), 200
    except Exception as e:
        logger.exception("[%s] referral_payouts failed account_id=%s", ROUTE_VERSION, account_id)
        return jsonify(
            {
                "ok": False,
                "route_version": ROUTE_VERSION,
                "error": "referral_payouts_failed",
                "root_cause": repr(e),
                "fix": "Check referral_payouts table structure and list_payouts_for_account logic.",
                "account_id": account_id,
                "debug": {"auth": debug},
            }
        ), 500
