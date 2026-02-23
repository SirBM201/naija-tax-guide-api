# app/routes/subscriptions.py
from __future__ import annotations

import os
from typing import Any, Dict

from flask import Blueprint, jsonify, request, g

from app.core.auth import require_auth_plus
from app.services.subscription_status_service import get_subscription_status
from app.services.subscriptions_service import activate_subscription_now

bp = Blueprint("subscriptions", __name__)

ADMIN_KEY = (os.getenv("ADMIN_KEY", "") or "").strip()


def _admin_key_configured() -> bool:
    return bool(ADMIN_KEY)


def _is_admin(req) -> bool:
    if not ADMIN_KEY:
        return False
    key = (req.headers.get("X-Admin-Key", "") or "").strip()
    return bool(key) and key == ADMIN_KEY


@bp.get("/subscription/status")
@require_auth_plus
def subscription_status():
    """
    Returns subscription status for the currently authenticated user.
    Works for cookie OR bearer (require_auth_plus sets g.account_id).
    """
    account_id = str(getattr(g, "account_id", "") or "").strip()
    status = get_subscription_status(account_id)
    return jsonify(status), 200


@bp.post("/subscription/activate")
def subscription_activate():
    """
    ADMIN ONLY: create/upsert a subscription row for testing

    Header:
      X-Admin-Key: <ADMIN_KEY>

    Body:
      {
        "account_id": "<uuid>",
        "plan_code": "monthly|quarterly|yearly|trial|manual",
        "status": "active" (optional),
        "expires_at": "2026-03-01T00:00:00Z" (optional),
        "grace_until": "2026-03-05T00:00:00Z" (optional),
        "trial_until": "2026-03-10T00:00:00Z" (optional)
      }
    """
    if not _admin_key_configured():
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "admin_key_not_configured",
                    "message": "ADMIN_KEY env var is not set on the server. Set it in Koyeb env vars, then retry.",
                }
            ),
            500,
        )

    if not _is_admin(request):
        got = bool((request.headers.get("X-Admin-Key", "") or "").strip())
        return (
            jsonify(
                {
                    "ok": False,
                    "error": "forbidden",
                    "message": "Admin key required." if not got else "Admin key invalid.",
                }
            ),
            403,
        )

    body: Dict[str, Any] = request.get_json(silent=True) or {}
    account_id = (body.get("account_id") or body.get("user_id") or "").strip()
    plan_code = (body.get("plan_code") or body.get("plan") or "manual").strip()
    status = (body.get("status") or "active").strip()

    expires_at = body.get("expires_at")
    grace_until = body.get("grace_until")
    trial_until = body.get("trial_until")

    if not account_id:
        return jsonify({"ok": False, "error": "missing_account_id"}), 400

    # ✅ FIX: use account_id keyword (NOT user_id)
    res = activate_subscription_now(
        account_id=account_id,
        plan_code=plan_code,
        status=status,
        expires_at_iso=expires_at,
        grace_until_iso=grace_until,
        trial_until_iso=trial_until,
    )

    code = 200 if res.get("ok") else 400
    return jsonify(res), code
