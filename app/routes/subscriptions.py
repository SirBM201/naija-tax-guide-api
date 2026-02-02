# app/routes/subscriptions.py
from flask import Blueprint, jsonify, request

from ..core.security import require_admin_key
from ..services.subscriptions_service import (
    get_subscription_status,
    start_trial_if_eligible,
    activate_subscription_now,
    schedule_plan_change_at_expiry,
    apply_scheduled_change_if_due,
    manual_activate_subscription,
)

bp = Blueprint("subscriptions", __name__)

@bp.get("/subscription/status")
def subscription_status():
    """
    Public: check subscription status.
    Query params (any one path works):
      - account_id=<uuid>
      OR
      - provider=telegram|whatsapp|... & provider_user_id=<id>
    """
    account_id = (request.args.get("account_id") or "").strip() or None
    provider = (request.args.get("provider") or "").strip() or None
    provider_user_id = (request.args.get("provider_user_id") or "").strip() or None

    out = get_subscription_status(account_id=account_id, provider=provider, provider_user_id=provider_user_id)
    return jsonify(out), 200


@bp.post("/subscription/activate")
def subscription_activate_manual():
    """
    Manual activation (admin only).
    Header: X-Admin-Key
    Body: { "account_id": "<uuid>", "plan_code": "monthly|quarterly|yearly", "expires_at": "<iso optional>" }
    """
    guard = require_admin_key()
    if guard is not None:
        return guard

    body = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or "").strip()
    plan_code = (body.get("plan_code") or "").strip() or None
    expires_at = (body.get("expires_at") or "").strip() or None

    if not account_id:
        return jsonify({"ok": False, "error": "account_id is required"}), 400

    sub = manual_activate_subscription(account_id=account_id, plan_code=plan_code, expires_at=expires_at)
    return jsonify({"ok": True, "subscription": sub}), 200


@bp.post("/subscription/trial")
def subscription_trial():
    """
    Start trial (admin-only for now).
    Header: X-Admin-Key
    Body: { "account_id": "<uuid>" }
    """
    guard = require_admin_key()
    if guard is not None:
        return guard

    body = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or "").strip()

    if not account_id:
        return jsonify({"ok": False, "error": "account_id is required"}), 400

    out = start_trial_if_eligible(account_id=account_id, trial_plan_code="trial")
    code = 200 if out.get("ok") else 400
    return jsonify(out), code


@bp.post("/subscription/change")
def subscription_change():
    """
    Upgrade/downgrade (admin-only for now).
    Header: X-Admin-Key
    Body:
      {
        "account_id": "<uuid>",
        "new_plan_code": "monthly|quarterly|yearly",
        "when": "now" | "at_expiry"
      }
    """
    guard = require_admin_key()
    if guard is not None:
        return guard

    body = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or "").strip()
    new_plan_code = (body.get("new_plan_code") or "").strip()
    when = (body.get("when") or "now").strip().lower()

    if not account_id or not new_plan_code:
        return jsonify({"ok": False, "error": "account_id and new_plan_code are required"}), 400

    if when == "at_expiry":
        row = schedule_plan_change_at_expiry(account_id=account_id, next_plan_code=new_plan_code)
        return jsonify({"ok": True, "scheduled": True, "subscription": row}), 200

    # Default: immediate change
    row = activate_subscription_now(account_id=account_id, plan_code=new_plan_code, status="active")
    return jsonify({"ok": True, "scheduled": False, "subscription": row}), 200


@bp.post("/subscription/apply-pending")
def subscription_apply_pending():
    """
    Optional helper endpoint (admin-only):
    Applies pending change if due right now.
    """
    guard = require_admin_key()
    if guard is not None:
        return guard

    body = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or "").strip()
    if not account_id:
        return jsonify({"ok": False, "error": "account_id is required"}), 400

    row = apply_scheduled_change_if_due(account_id)
    return jsonify({"ok": True, "applied": bool(row), "subscription": row}), 200
