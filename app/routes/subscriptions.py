from flask import Blueprint, jsonify, request
from ..core.security import require_admin_key
from ..services.subscriptions_service import (
    get_subscription_status,
    manual_activate_subscription,
)

bp = Blueprint("subscriptions", __name__)

@bp.get("/subscription/status")
def subscription_status():
    """
    Query params:
      - account_id (preferred) OR
      - provider + provider_user_id
    """
    account_id = (request.args.get("account_id") or "").strip()
    provider = (request.args.get("provider") or "").strip().lower()
    provider_user_id = (request.args.get("provider_user_id") or "").strip()

    status = get_subscription_status(
        account_id=account_id or None,
        provider=provider or None,
        provider_user_id=provider_user_id or None,
    )
    return jsonify({"ok": True, **status})

@bp.post("/subscription/activate")
def subscription_activate():
    """
    Admin-only manual activation.
    Header: X-Admin-Key

    Body:
      {
        "account_id": "<uuid>",
        "plan_code": "monthly|quarterly|yearly|pro|..." (optional),
        "expires_at": "2026-12-31T00:00:00Z" (optional)
      }
    If expires_at omitted, we auto-add 30 days.
    """
    guard = require_admin_key()
    if guard is not None:
        return guard

    body = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or "").strip()
    if not account_id:
        return jsonify({"ok": False, "error": "account_id is required"}), 400

    plan_code = (body.get("plan_code") or "").strip() or None
    expires_at = (body.get("expires_at") or "").strip() or None

    result = manual_activate_subscription(
        account_id=account_id,
        plan_code=plan_code,
        expires_at=expires_at,
    )
    return jsonify({"ok": True, "subscription": result})

