# app/routes/paystack_routes.py
from flask import Blueprint, jsonify

bp = Blueprint("paystack", __name__)

@bp.get("/paystack/health")
def paystack_health():
    return jsonify({"ok": True})
