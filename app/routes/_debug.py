# app/routes/_debug.py
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase

bp = Blueprint("_debug", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


DEBUG_ENABLED = _truthy(_env("DEBUG_ENDPOINTS_ENABLED", "1"))
ADMIN_KEY = _env("ADMIN_API_KEY", "")

WEB_OTP_TABLE = _env("WEB_OTP_TABLE", "web_otps")


def _is_admin(req) -> bool:
    # Allow turning off admin gating if you want (not recommended for prod)
    if _truthy(_env("DEBUG_ENDPOINTS_PUBLIC", "0")):
        return True
    got = (req.headers.get("X-Admin-Key") or "").strip()
    return bool(ADMIN_KEY) and got == ADMIN_KEY


@bp.get("/_debug/otp/latest")
def debug_latest_otp():
    if not DEBUG_ENABLED:
        return jsonify({"ok": False, "error": "debug_disabled"}), 403
    if not _is_admin(request):
        return jsonify({"ok": False, "error": "admin_required"}), 401

    email = (request.args.get("email") or "").strip().lower()
    contact = (request.args.get("contact") or "").strip().lower()
    target = email or contact
    if not target:
        return jsonify({"ok": False, "error": "missing_email_or_contact"}), 400

    # Try both schema variants safely
    # New schema: contact / code_hash / used
    # Legacy schema: phone_e164 / otp_hash / revoked
    try:
        q = (
            _sb()
            .table(WEB_OTP_TABLE)
            .select("id, created_at, expires_at, purpose, contact, code_hash, used")
            .eq("contact", target)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = (q.data or []) if hasattr(q, "data") else []
        if rows:
            row = rows[0]
            # never return hashes if you don’t want; but hashes are not secrets.
            safe = {
                "id": row.get("id"),
                "created_at": row.get("created_at"),
                "expires_at": row.get("expires_at"),
                "purpose": row.get("purpose"),
                "contact": row.get("contact"),
                "used": row.get("used"),
            }
            return jsonify({"ok": True, "row": safe, "schema": "contact/code_hash/used"}), 200
    except Exception:
        pass

    # Legacy schema fallback
    try:
        q2 = (
            _sb()
            .table(WEB_OTP_TABLE)
            .select("id, created_at, expires_at, device_id, phone_e164, otp_hash, revoked")
            .eq("phone_e164", target)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows2 = (q2.data or []) if hasattr(q2, "data") else []
        if rows2:
            row = rows2[0]
            safe = {
                "id": row.get("id"),
                "created_at": row.get("created_at"),
                "expires_at": row.get("expires_at"),
                "device_id": row.get("device_id"),
                "phone_e164": row.get("phone_e164"),
                "revoked": row.get("revoked"),
            }
            return jsonify({"ok": True, "row": safe, "schema": "phone_e164/otp_hash/revoked"}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": "debug_otp_failed", "root_cause": repr(e)}), 500

    return jsonify({"ok": False, "error": "no_rows_found"}), 404
