# app/routes/_debug.py
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase

bp = Blueprint("_debug", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or default).strip()


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def _require_admin() -> Optional[Dict[str, Any]]:
    """
    Lightweight admin guard.
    Uses X-Admin-Key if ADMIN_API_KEY is set.
    If ADMIN_API_KEY is not set, still allows in dev only.
    """
    env = _env("ENV", "prod").lower()
    admin_key = _env("ADMIN_API_KEY", "")
    incoming = (request.headers.get("X-Admin-Key") or "").strip()

    if admin_key:
        if incoming != admin_key:
            return {"ok": False, "error": "forbidden", "why": "missing_or_invalid_admin_key"}
        return None

    # no admin key configured
    if env == "dev":
        return None

    return {"ok": False, "error": "forbidden", "why": "admin_key_not_configured_in_prod"}


@bp.get("/_debug/config")
def debug_config():
    guard = _require_admin()
    if guard:
        return jsonify(guard), 403

    safe = {
        "ok": True,
        "env": _env("ENV", "prod"),
        "web_auth": {
            "WEB_AUTH_ENABLED": _env("WEB_AUTH_ENABLED", ""),
            "WEB_AUTH_DEBUG": _env("WEB_AUTH_DEBUG", ""),
            "WEB_OTP_TABLE": _env("WEB_OTP_TABLE", "web_otps"),
            "WEB_TOKEN_TABLE": _env("WEB_TOKEN_TABLE", "web_tokens"),
            "WEB_OTP_TTL_MINUTES": _env("WEB_OTP_TTL_MINUTES", "10"),
            "WEB_SESSION_TTL_DAYS": _env("WEB_SESSION_TTL_DAYS", "30"),
        },
    }
    return jsonify(safe), 200


@bp.get("/_debug/otp/latest")
def debug_otp_latest():
    guard = _require_admin()
    if guard:
        return jsonify(guard), 403

    table = _env("WEB_OTP_TABLE", "web_otps")
    contact = (request.args.get("email") or request.args.get("contact") or "").strip().lower()

    if not contact:
        return jsonify({"ok": False, "error": "missing_email_or_contact"}), 400

    # Choose safe columns dynamically (avoid non-existent columns like 'otp')
    cols: List[str] = []
    for c in [
        "id",
        "created_at",
        "contact",
        "purpose",
        "expires_at",
        "used",
        "used_at",
        "revoked",
        "revoked_at",
        "code_hash",
    ]:
        if _has_column(table, c):
            cols.append(c)

    # Must at least be able to select contact + expires_at to be meaningful
    if "contact" not in cols and not _has_column(table, "contact"):
        return jsonify({"ok": False, "error": "schema_mismatch", "why": "otp_table_missing_contact"}), 500

    select_cols = ",".join(cols) if cols else "*"

    try:
        q = (
            _sb()
            .table(table)
            .select(select_cols)
            .eq("contact", contact)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = (q.data or []) if hasattr(q, "data") else []
        if not rows:
            return jsonify({"ok": True, "found": False, "row": None}), 200

        row = rows[0]

        # remove any sensitive content (even though we never store plaintext OTP)
        # code_hash is OK for debugging but can be optionally removed:
        if not _truthy(_env("DEBUG_RETURN_CODE_HASH", "0")) and "code_hash" in row:
            row.pop("code_hash", None)

        return jsonify({"ok": True, "found": True, "row": row}), 200

    except Exception as e:
        return jsonify(
            {"ok": False, "error": "debug_otp_failed", "root_cause": repr(e)[:240]}
        ), 500
