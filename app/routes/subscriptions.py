# app/routes/subscriptions.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..core.security import require_admin_key
from ..services.subscriptions_service import (
    get_subscription_status,
    manual_activate_subscription,
    start_trial_if_eligible,
    activate_subscription_now,
    schedule_plan_change_at_expiry,
)

bp = Blueprint("subscriptions", __name__)


def _clean(s: str | None) -> str | None:
    v = (s or "").strip()
    return v or None


def _status_to_frontend_shape(status: dict) -> dict:
    """
    Frontend wants: plan_expiry (not expires_at).
    Keep backend canonical fields too, but add plan_expiry for UI.
    """
    out = dict(status or {})
    out["plan_expiry"] = out.get("expires_at")
    return out


@bp.get("/subscription/status")
def subscription_status():
    """
    Query params:
      - account_id
      - provider
      - provider_user_id
    Returns (frontend-safe):
      {
        active: bool,
        state: "none"|"active"|"expired",
        account_id: str|None,
        plan_code: str|None,
        expires_at: str|None,
        plan_expiry: str|None,
        reason: str
      }
    """
    account_id = _clean(request.args.get("account_id"))
    provider = _clean(request.args.get("provider"))
    provider_user_id = _clean(request.args.get("provider_user_id"))

    status = get_subscription_status(
        account_id=account_id,
        provider=provider,
        provider_user_id=provider_user_id,
    )

    return jsonify(_status_to_frontend_shape(status)), 200


@bp.post("/subscription/activate")
def subscription_activate():
    """
    Admin-only manual activation.
    Header: X-Admin-Key
    Body:
      {
        "account_id": "<uuid>",
        "plan_code": "monthly|quarterly|yearly|trial|manual",
        "expires_at": "2026-03-01T00:00:00Z"   (optional)
      }
    """
    guard = require_admin_key()
    if guard is not None:
        return guard

    body = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or "").strip()
    plan_code = (body.get("plan_code") or "").strip() or "manual"
    expires_at = _clean(body.get("expires_at"))

    if not account_id:
        return jsonify({"ok": False, "error": "account_id is required"}), 400

    try:
        sub = manual_activate_subscription(
            account_id=account_id,
            plan_code=plan_code,
            expires_at=expires_at,
        )
        return jsonify({"ok": True, "subscription": sub, "plan_expiry": sub.get("expires_at")}), 200
    except Exception:
        # avoid leaking internals
        return jsonify({"ok": False, "error": "activation_failed"}), 400


@bp.post("/subscription/trial")
def subscription_trial():
    """
    Admin-only trial start (for now).
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
    if out.get("ok") and isinstance(out.get("subscription"), dict):
        out["plan_expiry"] = out["subscription"].get("expires_at")

    return jsonify(out), (200 if out.get("ok") else 400)


@bp.post("/subscription/change")
def subscription_change():
    """
    Admin-only change.
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
    new_plan_code = (body.get("new_plan_code") or "").strip().lower()
    when = (body.get("when") or "now").strip().lower()

    if not account_id or not new_plan_code:
        return jsonify({"ok": False, "error": "account_id and new_plan_code are required"}), 400

    try:
        if when == "at_expiry":
            sub = schedule_plan_change_at_expiry(account_id=account_id, next_plan_code=new_plan_code)
            return jsonify({"ok": True, "mode": "scheduled", "subscription": sub, "plan_expiry": sub.get("expires_at")}), 200

        sub = activate_subscription_now(account_id=account_id, plan_code=new_plan_code, status="active")
        return jsonify({"ok": True, "mode": "activated", "subscription": sub, "plan_expiry": sub.get("expires_at")}), 200
    except Exception:
        # avoid leaking internals
        return jsonify({"ok": False, "error": "change_failed"}), 400
