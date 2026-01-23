# app/routes/health.py
from flask import Blueprint, jsonify
from app.core.utils import now_utc, iso

bp = Blueprint("health", __name__)

@bp.get("/health")
def health():
    return jsonify({"ok": True, "service": "naija-tax-guide", "time_utc": iso(now_utc())})
