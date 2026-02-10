from flask import Blueprint, jsonify, request
import os

from app.core.supabase_client import supabase

bp = Blueprint("accounts_admin", __name__)
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

def _bad(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status

@bp.post("/admin/accounts/unlink")
def admin_unlink_account():
    admin_key = (request.headers.get("X-Admin-Key") or "").strip()
    if not ADMIN_API_KEY or admin_key != ADMIN_API_KEY:
        return _bad("Unauthorized", 401)

    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if provider not in ("wa", "tg"):
        return _bad("provider must be wa or tg")
    if not provider_user_id:
        return _bad("provider_user_id required")

    try:
        res = (
            supabase()
            .table("accounts")
            .update({"auth_user_id": None})
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .execute()
        )
    except Exception as e:
        return _bad(f"DB error: {str(e)}", 500)

    return jsonify({"ok": True, "unlinked": True, "rows": len(res.data or [])})
