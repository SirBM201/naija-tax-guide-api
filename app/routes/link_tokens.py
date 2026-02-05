from flask import Blueprint, jsonify, request
import os
import re
from app.core.supabase_client import supabase

bp = Blueprint("link_tokens", __name__)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()
CODE_RE = re.compile(r"^[A-Z0-9]{6,12}$")

def _bad(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status

@bp.post("/link-tokens/create")
def create_link_token_api():
    admin_key = (request.headers.get("X-Admin-Key") or "").strip()
    if not ADMIN_API_KEY or admin_key != ADMIN_API_KEY:
        return _bad("Unauthorized", 401)

    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    ttl_minutes = int(body.get("ttl_minutes") or 30)

    if provider not in ("wa", "tg"):
        return _bad("provider must be wa or tg")
    if ttl_minutes < 5 or ttl_minutes > 1440:
        return _bad("ttl_minutes must be between 5 and 1440")

    try:
        res = supabase().rpc("create_link_token_admin", {
            "p_provider": provider,
            "p_ttl_minutes": ttl_minutes
        }).execute()
    except Exception as e:
        return _bad(f"RPC error: {str(e)}", 500)

    row = (res.data or [None])[0]
    if not row or not row.get("ok"):
        return jsonify({"ok": False, "provider": provider, "error": row or "Token creation failed"}), 400

    return jsonify({
        "ok": True,
        "provider": provider,
        "code": row.get("code"),
        "token_id": row.get("token_id"),
        "expires_at": row.get("expires_at"),
    })

@bp.post("/link-tokens/consume")
def consume_link_token_api():
    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    code = (body.get("code") or "").strip().upper()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if provider not in ("wa", "tg"):
        return _bad("provider must be wa or tg")
    if not code or not CODE_RE.match(code):
        return _bad("Invalid code format")
    if not provider_user_id:
        return _bad("provider_user_id required")

    try:
        res = supabase().rpc("consume_link_token", {
            "p_provider": provider,
            "p_code": code,
            "p_provider_user_id": provider_user_id
        }).execute()
    except Exception as e:
        return _bad(f"RPC error: {str(e)}", 500)

    row = (res.data or [None])[0]
    if not row or not row.get("ok"):
        return jsonify({"ok": False, "provider": provider, "message": "Invalid or expired code"}), 400

    return jsonify({
        "ok": True,
        "provider": provider,
        "auth_user_id": row.get("auth_user_id"),
        "token_id": row.get("token_id"),
        "expires_at": row.get("expires_at"),
    })
