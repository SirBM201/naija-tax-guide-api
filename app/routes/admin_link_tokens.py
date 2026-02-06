from flask import Blueprint, jsonify, request
import os

from app.core.supabase_client import supabase

bp = Blueprint("admin_link_tokens", __name__)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()


def _bad(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status


def _require_admin(req):
    admin_key = (req.headers.get("X-Admin-Key") or "").strip()
    if not ADMIN_API_KEY or admin_key != ADMIN_API_KEY:
        return False
    return True


@bp.post("/admin/link-tokens/create")
def admin_create_link_token():
    """
    Admin dashboard token creation.
    Body:
      {
        "provider": "wa" | "tg",
        "ttl_minutes": 30,
        "auth_user_id": "<uuid>"
      }
    Returns code once (not stored raw in DB).
    """
    if not _require_admin(request):
        return _bad("Unauthorized", 401)

    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    ttl_minutes = int(body.get("ttl_minutes") or 30)
    auth_user_id = (body.get("auth_user_id") or "").strip()

    if provider not in ("wa", "tg"):
        return _bad("provider must be wa or tg")
    if ttl_minutes < 5 or ttl_minutes > 1440:
        return _bad("ttl_minutes must be between 5 and 1440")
    if not auth_user_id:
        return _bad("auth_user_id required")

    try:
        res = supabase().rpc(
            "create_link_token",
            {"p_provider": provider, "p_auth_user_id": auth_user_id, "p_ttl_minutes": ttl_minutes},
        ).execute()
    except Exception as e:
        return _bad(f"RPC error: {str(e)}", 500)

    row = (res.data or [None])[0]
    if not row or not row.get("ok"):
        return jsonify({"ok": False, "provider": provider, "error": row or "Token creation failed"}), 400

    return jsonify(
        {
            "ok": True,
            "provider": provider,
            "code": row.get("code"),
            "token_id": row.get("token_id"),
            "expires_at": row.get("expires_at"),
        }
    )


@bp.get("/admin/link-tokens/recent")
def admin_recent_link_tokens():
    """
    Admin dashboard listing (NO raw code; only status).
    Query params:
      provider=wa|tg (optional)
      auth_user_id=<uuid> (optional)
      limit=50 (optional)
    """
    if not _require_admin(request):
        return _bad("Unauthorized", 401)

    provider = (request.args.get("provider") or "").strip().lower()
    auth_user_id = (request.args.get("auth_user_id") or "").strip()
    limit = int(request.args.get("limit") or 50)
    limit = max(1, min(limit, 200))

    q = (
        supabase()
        .table("link_tokens")
        .select("id, provider, auth_user_id, provider_user_id, created_at, expires_at, used_at")
        .order("created_at", desc=True)
        .limit(limit)
    )

    if provider in ("wa", "tg"):
        q = q.eq("provider", provider)
    if auth_user_id:
        q = q.eq("auth_user_id", auth_user_id)

    try:
        res = q.execute()
    except Exception as e:
        return _bad(f"DB error: {str(e)}", 500)

    return jsonify({"ok": True, "items": res.data or []})


@bp.post("/admin/link-tokens/revoke")
def admin_revoke_link_token():
    """
    Optional: revoke a token by setting used_at = now() (so it cannot be consumed).
    Body: { "token_id": "<uuid>" }
    """
    if not _require_admin(request):
        return _bad("Unauthorized", 401)

    body = request.get_json(silent=True) or {}
    token_id = (body.get("token_id") or "").strip()
    if not token_id:
        return _bad("token_id required")

    try:
        res = (
            supabase()
            .table("link_tokens")
            .update({"used_at": "now()"})
            .eq("id", token_id)
            .execute()
        )
    except Exception as e:
        return _bad(f"DB error: {str(e)}", 500)

    return jsonify({"ok": True, "updated": res.data or []})
