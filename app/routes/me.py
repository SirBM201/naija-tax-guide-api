# app/routes/me.py
from flask import Blueprint, jsonify
from app.core.supabase_client import supabase
from app.services.auth_service import get_current_user

bp = Blueprint("me", __name__)

@bp.get("/me")
def me():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    sb = supabase()
    uid = user["id"]

    # accounts table must have supabase_user_id column (text/uuid)
    res = sb.table("accounts").select("id").eq("supabase_user_id", uid).limit(1).execute()
    if res.data:
        return jsonify({"ok": True, "account_id": res.data[0]["id"], "user_id": uid})

    # Create account if missing (one-time)
    created = sb.table("accounts").insert({"supabase_user_id": uid, "provider": "web"}).execute()
    return jsonify({"ok": True, "account_id": created.data[0]["id"], "user_id": uid})
