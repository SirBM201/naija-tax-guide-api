# app/core/security.py
from __future__ import annotations

import os
from typing import Optional

from flask import jsonify, request


def require_admin_key() -> Optional[tuple]:
    """
    Returns a Flask response tuple (json, status) if unauthorized, otherwise None.
    NEVER raises.
    """
    try:
        expected = (os.getenv("ADMIN_KEY") or "").strip()
        if not expected:
            # Server misconfig (not user's fault)
            return jsonify({"ok": False, "error": "admin_key_not_configured"}), 500

        got = (request.headers.get("X-Admin-Key") or "").strip()
        if not got:
            return jsonify({"ok": False, "error": "missing_admin_key_header"}), 401

        if got != expected:
            return jsonify({"ok": False, "error": "invalid_admin_key"}), 401

        return None
    except Exception as e:
        # Absolute last-resort safety net
        return jsonify({"ok": False, "error": "admin_guard_crashed", "message": str(e)[:500]}), 500
