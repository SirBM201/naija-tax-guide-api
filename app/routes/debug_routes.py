from flask import Blueprint, jsonify, current_app

bp = Blueprint("debug_routes", __name__)

@bp.get("/_routes")
def list_routes():
    out = []
    for r in current_app.url_map.iter_rules():
        if r.rule.startswith("/static"):
            continue
        out.append({"rule": r.rule, "methods": sorted([m for m in r.methods if m not in ("HEAD", "OPTIONS")])})
    return jsonify({"ok": True, "routes": out})
