# app/routes/link_tokens.py

import os
import secrets
import string
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify
from supabase import create_client

# --------------------------------------------------
# ENV / SUPABASE
# --------------------------------------------------

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("SUPABASE env vars missing")

sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

bp = Blueprint("link_tokens", __name__, url_prefix="/link")


# --------------------------------------------------
# CONFIG
# --------------------------------------------------

TOKEN_LENGTH = 8
TOKEN_EXPIRY_MINUTES = 30


def generate_code(length: int = TOKEN_LENGTH) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# --------------------------------------------------
# 1️⃣ GENERATE LINK CODE (Website side)
# --------------------------------------------------

@bp.post("/generate")
def generate_link_code():
    """
    Body:
    {
        "auth_user_id": "<uuid>",
        "provider": "wa" | "tg"
    }
    """

    body = request.get_json(silent=True) or {}

    auth_user_id = body.get("auth_user_id")
    provider = (body.get("provider") or "").lower()

    if not auth_user_id or provider not in ("wa", "tg"):
        return jsonify({"ok": False, "error": "Invalid request"}), 400

    code = generate_code()

    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRY_MINUTES
    )

    # Insert token
    sb.table("link_tokens").insert({
        "code": code,
        "auth_user_id": auth_user_id,
        "provider": provider,
        "expires_at": expires_at.isoformat(),
        "used": False
    }).execute()

    return jsonify({
        "ok": True,
        "code": code,
        "expires_in_minutes": TOKEN_EXPIRY_MINUTES
    })


# --------------------------------------------------
# 2️⃣ CONSUME LINK CODE (Chat side)
# --------------------------------------------------

@bp.post("/consume")
def consume_link_code():
    """
    Body:
    {
        "code": "<8-char>",
        "provider": "wa" | "tg",
        "provider_user_id": "<chat id>"
    }
    """

    body = request.get_json(silent=True) or {}

    code = (body.get("code") or "").upper()
    provider = (body.get("provider") or "").lower()
    provider_user_id = body.get("provider_user_id")

    if not code or provider not in ("wa", "tg") or not provider_user_id:
        return jsonify({"ok": False, "error": "Invalid request"}), 400

    # Fetch token
    res = sb.table("link_tokens") \
        .select("*") \
        .eq("code", code) \
        .eq("provider", provider) \
        .single() \
        .execute()

    token = res.data

    if not token:
        return jsonify({"ok": False, "error": "Invalid code"}), 404

    if token["used"]:
        return jsonify({"ok": False, "error": "Code already used"}), 400

    if datetime.fromisoformat(token["expires_at"]) < datetime.now(timezone.utc):
        return jsonify({"ok": False, "error": "Code expired"}), 400

    auth_user_id = token["auth_user_id"]

    # Link account
    sb.table("accounts").upsert({
        "provider": provider,
        "provider_user_id": provider_user_id,
        "auth_user_id": auth_user_id,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }).execute()

    # Mark token used
    sb.table("link_tokens") \
        .update({"used": True}) \
        .eq("code", code) \
        .execute()

    return jsonify({
        "ok": True,
        "linked": True
    })
