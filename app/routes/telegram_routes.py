# app/routes/telegram_routes.py
from flask import Blueprint, jsonify

bp = Blueprint("telegram", __name__)

@bp.get("/telegram/health")
def telegram_health():
    return jsonify({"ok": True, "module": "telegram_routes"})
