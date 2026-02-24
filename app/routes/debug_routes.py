# app/routes/debug_routes.py
from __future__ import annotations

from flask import Blueprint, jsonify, current_app, request

from app.core.security import require_admin_key


bp = Blueprint("debug_routes", __name__)


@bp.get("/_debug/routes")
def list_routes():
    guard = require_admin_key()
    if guard is not None:
        return guard

    out = []
    for rule in sorted(current_app.url_map.iter_rules(), key=lambda r: r.rule):
        methods = sorted([m for m in rule.methods if m not in ("HEAD", "OPTIONS")])
        out.append({"rule": rule.rule, "methods": methods, "endpoint": rule.endpoint})

    return jsonify({"ok": True, "count": len(out), "routes": out}), 200
