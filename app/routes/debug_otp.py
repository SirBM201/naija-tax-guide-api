from __future__ import annotations

import os
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request

bp = Blueprint("debug_otp", __name__)

# -----------------------------
# Admin protection (REQUIRED)
# -----------------------------
def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}

def _require_admin() -> Optional[Dict[str, Any]]:
    """
    Returns an error dict if not authorized, else None.
    You MUST set ADMIN_KEY in Koyeb env for this to work.
    """
    admin_key = (os.getenv("ADMIN_KEY") or os.getenv("X_ADMIN_KEY") or "").strip()
    if not admin_key:
        # safer: do not expose OTP if admin key isn't configured
        return {"ok": False, "error": "admin_key_not_configured", "message": "Set ADMIN_KEY env var to use debug otp."}

    got = (request.headers.get("X-Admin-Key") or "").strip()
    if got != admin_key:
        return {"ok": False, "error": "unauthorized", "message": "Missing/invalid X-Admin-Key."}

    return None


def _get_supabase_client():
    """
    Supports BOTH patterns:
    - supabase is already a client
    - supabase is a function that returns a client
    """
    try:
        from app.core.supabase_client import supabase  # type: ignore
    except Exception as e:
        return None, f"import_failed: {repr(e)}"

    try:
        client = supabase() if callable(supabase) else supabase
        return client, None
    except Exception as e:
        return None, f"client_init_failed: {repr(e)}"


@bp.get("/_debug/otp/latest")
def latest_otp():
    # admin-only
    deny = _require_admin()
    if deny:
        return jsonify(deny), 401 if deny.get("error") == "unauthorized" else 500

    email = (request.args.get("email") or "").strip()
    phone = (request.args.get("phone") or "").strip()
    identifier = (request.args.get("q") or request.args.get("identifier") or "").strip()

    # pick first non-empty
    key = email or phone or identifier
    if not key:
        return jsonify({"ok": False, "error": "missing_identifier", "message": "Provide ?email= or ?phone= or ?identifier=/q="}), 400

    sb, err = _get_supabase_client()
    if sb is None:
        return jsonify({"ok": False, "error": "debug_otp_failed", "root_cause": err}), 500

    try:
        # Try common schema patterns without assuming too much.
        # You can adjust these column names if your table differs.
        q = sb.table("web_otps").select(
            "otp, email, phone, identifier, created_at, expires_at, consumed_at"
        )

        # Apply best filter based on which param used
        if email:
            q = q.eq("email", email)
        elif phone:
            q = q.eq("phone", phone)
        else:
            # identifier may be stored in "email" OR "identifier"
            # Try identifier column first; if your table doesn't have it, Supabase will error and we'll catch.
            try:
                q = q.eq("identifier", identifier)
            except Exception:
                q = q.eq("email", identifier)

        res = q.order("created_at", desc=True).limit(1).execute()
        rows = (res.data or []) if hasattr(res, "data") else []
        if not rows:
            return jsonify({"ok": True, "found": False, "message": "No OTP rows found for identifier."})

        row = rows[0]

        # DO NOT leak more than needed
        return jsonify(
            {
                "ok": True,
                "found": True,
                "otp": row.get("otp"),
                "created_at": row.get("created_at"),
                "expires_at": row.get("expires_at"),
                "consumed_at": row.get("consumed_at"),
                "matched_on": "email" if email else ("phone" if phone else "identifier"),
            }
        )
    except Exception as e:
        return jsonify({"ok": False, "error": "debug_otp_failed", "root_cause": repr(e)}), 500
