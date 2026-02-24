# app/routes/subscriptions.py
from __future__ import annotations

import os
from typing import Any, Dict

from flask import Blueprint, jsonify, request

from app.services.subscriptions_service import (
    activate_subscription_now,
    get_subscription_status,
)

bp = Blueprint("subscriptions", __name__)


def _admin_ok(req) -> bool:
    expected = (os.getenv("ADMIN_KEY") or "").strip()
    got = (req.headers.get("X-Admin-Key") or "").strip()
    return bool(expected) and got == expected


@bp.post("/subscription/activate")
def admin_activate():
    if not _admin_ok(request):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    account_id = (payload.get("account_id") or "").strip()
    plan_code = (payload.get("plan_code") or "monthly").strip()
    days = payload.get("days")

    out = activate_subscription_now(account_id=account_id, plan_code=plan_code, days=days)
    return jsonify(out), (200 if out.get("ok") else 400)


@bp.get("/subscription/status/<account_id>")
def status(account_id: str):
    out = get_subscription_status(account_id=account_id)
    return jsonify(out), (200 if out.get("ok") else 400)
