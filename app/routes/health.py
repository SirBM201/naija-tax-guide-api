# app/routes/health.py
from flask import Blueprint, current_app, jsonify

bp = Blueprint("health", __name__)

@bp.get("/health")
def health():
    return jsonify({"ok": True})

@bp.get("/routes")
def routes_list():
    items = []
    for rule in sorted(current_app.url_map.iter_rules(), key=lambda r: str(r)):
        if rule.endpoint == "static":
            continue
        items.append({
            "rule": str(rule),
            "methods": sorted([m for m in rule.methods if m in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")]),
            "endpoint": rule.endpoint,
        })
    return jsonify({"ok": True, "routes": items})
