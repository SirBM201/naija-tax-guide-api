# app/routes/billing.py
from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.plans_service import get_plan, list_plans

bp = Blueprint("billing", __name__)


@bp.get("/billing/plans")
def billing_plans():
    """
    Returns available plans for the frontend.
    Uses DB table 'plans' if available; otherwise returns safe defaults.
    """
    active_only = (request.args.get("active_only") or "1").strip() != "0"
    plans = list_plans(active_only=active_only)
    return jsonify({"ok": True, "plans": plans}), 200


@bp.get("/billing/plans/<plan_code>")
def billing_plan(plan_code: str):
    """
    Returns a single plan details by plan_code.
    """
    p = get_plan(plan_code)
    if not p:
        return jsonify({"ok": False, "error": "plan_not_found"}), 404
    return jsonify({"ok": True, "plan": p}), 200
