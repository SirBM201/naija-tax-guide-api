from __future__ import annotations

import os
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase

bp = Blueprint("debug_otp", __name__)

def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}

def _require_admin() -> Optional[Dict[str, Any]]:
    # Reuse your existing admin key behavior
    expected = (os.getenv("ADMIN_KEY") or os.getenv("X_ADMIN_KEY") or "").strip()
    if not expected:
        return {"ok": False, "error": "admin_key_not_configured", "hint": "Set ADMIN_KEY env var on Koyeb."}

    got = (request.headers.get("X-Admin-Key") or "").strip()
    if got != expected:
        return {"ok": False, "error": "unauthorized", "hint": "Missing/invalid X-Admin-Key."}
    return None


@bp.get("/_debug/otp/latest")
def debug_otp_latest():
    err = _require_admin()
    if err:
        return jsonify(err), 401

    email = (request.args.get("email") or "").strip().lower()
    phone = (request.args.get("phone") or "").strip()

    if not email and not phone:
        return jsonify({"ok": False, "error": "bad_request", "hint": "Provide ?email= or ?phone="}), 400

    try:
        q = supabase.table("web_otps").select("*").order("created_at", desc=True).limit(1)
        if email:
            q = q.eq("email", email)
        if phone:
            q = q.eq("phone", phone)

        res = q.execute()
        rows = (res.data or []) if hasattr(res, "data") else []
        row = rows[0] if rows else None

        return jsonify({"ok": True, "email": email or None, "phone": phone or None, "otp_row": row}), 200
    except Exception as e:
        # root-cause exposer
        return jsonify({"ok": False, "error": "debug_otp_failed", "root_cause": repr(e)}), 500
