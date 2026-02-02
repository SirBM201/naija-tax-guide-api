from flask import Blueprint, jsonify, request
from ..core.security import require_admin_key
from ..services.subscriptions_service import get_subscription_status

# TEMP fallback so the app boots even if the function is missing
def manual_activate_subscription(*args, **kwargs):
    raise RuntimeError("manual_activate_subscription not implemented in subscriptions_service.py")

bp = Blueprint("subscriptions", __name__)

@bp.post("/subscription/trial")
def subscription_trial():
    """
    Start trial for an account (admin-only for now).
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

    out = start_trial(account_id=account_id)
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
        "change_type": "upgraded|downgraded"
      }
    """
    guard = require_admin_key()
    if guard is not None:
        return guard

    body = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or "").strip()
    new_plan_code = (body.get("new_plan_code") or "").strip()
    change_type = (body.get("change_type") or "upgraded").strip().lower()

    if not account_id or not new_plan_code:
        return jsonify({"ok": False, "error": "account_id and new_plan_code are required"}), 400

    if change_type not in ("upgraded", "downgraded"):
        change_type = "upgraded"

    out = change_plan(account_id=account_id, new_plan_code=new_plan_code, change_type=change_type)
    return jsonify(out), 200
