from flask import request, jsonify
from .config import ADMIN_API_KEY

def require_admin_key():
    """
    Simple header-based admin guard for manual subscription activation.
    Header: X-Admin-Key: <ADMIN_API_KEY>
    """
    if not ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "ADMIN_API_KEY not configured"}), 500

    got = (request.headers.get("X-Admin-Key") or "").strip()
    if got != ADMIN_API_KEY:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    return None
