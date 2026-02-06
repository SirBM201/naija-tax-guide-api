# app/routes/link_tokens.py
from flask import Blueprint, jsonify, request
import os
import re
import uuid

from app.core.supabase_client import supabase
from app.services.accounts_service import upsert_account_link

bp = Blueprint("link_tokens", __name__)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()

# Non-ambiguous: 23456789 + A..Z without I,O,L
CODE_RE = re.compile(r"^[23456789ABCDEFGHJKMNPQRSTUVWXYZ]{8}$")

ALLOWED_PROVIDERS = ("wa", "tg", "msgr", "ig", "email")


def _bad(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except Exception:
        return False


@bp.get("/link-tokens/health")
def link_tokens_health():
    return jsonify({"ok": True, "service": "link_tokens"})


@bp.post("/link-tokens/create")
def create_link_token_api():
    admin_key = (request.headers.get("X-Admin-Key") or "").strip()
    if not ADMIN_API_KEY or admin_key != ADMIN_API_KEY:
        return _bad("Unauthorized", 401)

    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    ttl_minutes = int(body.get("ttl_minutes") or 30)
    auth_user_id = (body.get("auth_user_id") or "").strip()

    if provider not in ALLOWED_PROVIDERS:
        return _bad(f"provider must be one of {ALLOWED_PROVIDERS}")
    if ttl_minutes < 5 or ttl_minutes > 1440:
        return _bad("ttl_minutes must be between 5 and 1440")
    if not auth_user_id:
        return _bad("auth_user_id required (uuid)")
    if not _is_uuid(auth_user_id):
        return _bad("auth_user_id must be a valid uuid")

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


@bp.post("/link-tokens/consume")
def consume_link_token_api():
    """
    Consumes token (RPC) then links account mapping (safe).
    """
    body = request.get_json(silent=True) or {}
    provider = (body.get("provider") or "").strip().lower()
    code = (body.get("code") or "").strip().upper()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    display_name = body.get("display_name")
    phone = body.get("phone")

    if provider not in ALLOWED_PROVIDERS:
        return _bad(f"provider must be one of {ALLOWED_PROVIDERS}")
    if not code or not CODE_RE.match(code):
        return _bad("Invalid code format (must be 8 chars non-ambiguous)")
    if not provider_user_id:
        return _bad("provider_user_id required")

    try:
        res = supabase().rpc(
            "consume_link_token",
            {"p_provider": provider, "p_code": code, "p_provider_user_id": provider_user_id},
        ).execute()
    except Exception as e:
        return _bad(f"RPC error: {str(e)}", 500)

    row = (res.data or [None])[0]
    if not row or not row.get("ok"):
        msg = (row or {}).get("message") if isinstance(row, dict) else None
        return jsonify({"ok": False, "provider": provider, "message": msg or "Invalid or expired code"}), 400

    auth_user_id = row.get("auth_user_id")
    token_id = row.get("token_id")
    expires_at = row.get("expires_at")

    if not auth_user_id:
        return _bad("consume_link_token returned no auth_user_id", 500)

    link = upsert_account_link(
        provider=provider,
        provider_user_id=provider_user_id,
        auth_user_id=auth_user_id,
        display_name=display_name,
        phone=phone,
    )

    if not link.get("ok"):
        return jsonify(
            {
                "ok": False,
                "provider": provider,
                "message": link.get("error") or "Failed to link channel",
                "reason": link.get("reason"),
            }
        ), 409

    return jsonify(
        {
            "ok": True,
            "provider": provider,
            "auth_user_id": auth_user_id,
            "token_id": token_id,
            "expires_at": expires_at,
            "account": link.get("account"),
        }
    )
