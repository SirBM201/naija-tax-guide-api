# app/routes/paystack_debug.py
from __future__ import annotations

import os
from flask import Blueprint, request, jsonify
from app.services.paystack_service import verify_transaction

bp = Blueprint("paystack_debug", __name__)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

@bp.get("/paystack/debug/verify")
def debug_verify():
    key = request.headers.get("x-admin-key", "")
    if not ADMIN_API_KEY or key != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    ref = (request.args.get("reference") or "").strip()
    if not ref:
        return jsonify({"ok": False, "error": "reference is required"}), 400

    data = verify_transaction(ref)
    # return only safe subset
    v = data.get("data") or {}
    return jsonify({
        "ok": True,
        "status": v.get("status"),
        "amount": v.get("amount"),
        "currency": v.get("currency"),
        "reference": v.get("reference"),
    }), 200
