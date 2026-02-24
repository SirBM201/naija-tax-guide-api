# app/routes/subscriptions.py
from __future__ import annotations

import os
import uuid
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.services.subscriptions_service import (
    activate_subscription_now,
    debug_read_subscription,
    debug_expose_subscription_health,
)

bp = Blueprint("subscriptions", __name__)


# -----------------------------------------------------------------------------
# Admin guard
# -----------------------------------------------------------------------------
def _admin_key() -> str:
    # Add aliases here if you use different names across environments
    return (os.getenv("ADMIN_KEY") or os.getenv("X_ADMIN_KEY") or os.getenv("BMS_ADMIN_KEY") or "").strip()


def _is_admin(req) -> bool:
    want = _admin_key()
    got = (req.headers.get("X-Admin-Key") or "").strip()
    return bool(want) and got == want


def _rootcause(where: str, e: Exception, *, req_id: str, hint: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"where": where, "type": type(e).__name__, "message": str(e), "request_id": req_id}
    if hint:
        out["hint"] = hint
    if extra:
        out["extra"] = extra
    return out


def _fail(status: int, error: str, *, req_id: str, message: Optional[str] = None, root_cause: Optional[Dict[str, Any]] = None, extra: Optional[Dict[str, Any]] = None):
    payload: Dict[str, Any] = {"ok": False, "error": error, "request_id": req_id}
    if message:
        payload["message"] = message
    if root_cause:
        payload["root_cause"] = root_cause
    if extra:
        payload["extra"] = extra
    return jsonify(payload), status


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@bp.post("/subscription/activate")
def subscription_activate():
    """
    Admin endpoint to activate a subscription immediately.
    Body JSON:
      { "account_id": "<uuid>", "plan_code": "monthly|quarterly|yearly", "days": optional_int }
    """
    req_id = str(uuid.uuid4())

    if not _is_admin(request):
        return _fail(
            401,
            "unauthorized",
            req_id=req_id,
            root_cause={"where": "admin_guard", "message": "Missing/invalid X-Admin-Key", "request_id": req_id},
        )

    try:
        body = request.get_json(silent=True) or {}
        account_id = (body.get("account_id") or "").strip()
        plan_code = (body.get("plan_code") or "monthly").strip()
        days = body.get("days", None)

        if not account_id:
            return _fail(400, "missing_account_id", req_id=req_id)

        if days is not None:
            try:
                days = int(days)
            except Exception:
                return _fail(
                    400,
                    "invalid_days",
                    req_id=req_id,
                    root_cause={"where": "input.days", "message": "days must be an integer", "request_id": req_id},
                )

        result = activate_subscription_now(account_id=account_id, plan_code=plan_code, days=days)

        if not result.get("ok"):
            # normalize request_id
            result.setdefault("request_id", req_id)
            if isinstance(result.get("root_cause"), dict):
                result["root_cause"].setdefault("request_id", req_id)

            err = (result.get("error") or "").lower()
            status = 400 if err.startswith(("missing_", "invalid_")) else 500
            return jsonify(result), status

        result["request_id"] = req_id
        return jsonify(result), 200

    except Exception as e:
        return _fail(
            500,
            "internal_error",
            req_id=req_id,
            root_cause=_rootcause(
                "routes.subscriptions.subscription_activate",
                e,
                req_id=req_id,
                hint="Unexpected exception in route handler. Check logs by request_id.",
            ),
        )


@bp.get("/_debug/subscription")
def debug_subscription():
    """
    Admin debug read.
    Query: ?account_id=<uuid>
    """
    req_id = str(uuid.uuid4())

    if not _is_admin(request):
        return _fail(
            401,
            "unauthorized",
            req_id=req_id,
            root_cause={"where": "admin_guard", "message": "Missing/invalid X-Admin-Key", "request_id": req_id},
        )

    try:
        account_id = (request.args.get("account_id") or "").strip()
        if not account_id:
            return _fail(400, "missing_account_id", req_id=req_id)

        result = debug_read_subscription(account_id)
        result.setdefault("request_id", req_id)
        return jsonify(result), (200 if result.get("ok") else 500)

    except Exception as e:
        return _fail(
            500,
            "internal_error",
            req_id=req_id,
            root_cause=_rootcause(
                "routes.subscriptions.debug_subscription",
                e,
                req_id=req_id,
                hint="Unexpected exception in debug handler. Check logs by request_id.",
            ),
        )


@bp.get("/_debug/subscription_health")
def debug_subscription_health():
    """
    Admin diagnostic endpoint.
    Query: optional ?account_id=<uuid> (used only for rpc probe)
    Returns: PowerShell-friendly shallow JSON with recommended SQL strings.
    """
    req_id = str(uuid.uuid4())

    if not _is_admin(request):
        return _fail(
            401,
            "unauthorized",
            req_id=req_id,
            root_cause={"where": "admin_guard", "message": "Missing/invalid X-Admin-Key", "request_id": req_id},
        )

    try:
        account_id = (request.args.get("account_id") or "").strip() or None
        result = debug_expose_subscription_health(account_id)

        # normalize request id
        result.setdefault("request_id", req_id)
        if isinstance(result.get("root_cause"), dict):
            result["root_cause"].setdefault("request_id", req_id)

        return jsonify(result), (200 if result.get("ok") else 500)

    except Exception as e:
        return _fail(
            500,
            "internal_error",
            req_id=req_id,
            root_cause=_rootcause(
                "routes.subscriptions.debug_subscription_health",
                e,
                req_id=req_id,
                hint="Unexpected exception in health exposer. Check logs by request_id.",
            ),
        )
