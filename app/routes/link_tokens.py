from __future__ import annotations

import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request
from supabase import create_client

from app.services.web_auth_service import get_account_id_from_request

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    raise RuntimeError("SUPABASE env vars missing")

sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

bp = Blueprint("link_tokens", __name__, url_prefix="/link")

TOKEN_LENGTH = 8
TOKEN_EXPIRY_MINUTES = 30


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_code(length: int = TOKEN_LENGTH) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _json_error(message: str, status: int = 400, **extra: Any):
    payload: Dict[str, Any] = {"ok": False, "error": message}
    payload.update(extra)
    return jsonify(payload), status


def _normalize_provider(raw: str) -> str:
    v = (raw or "").strip().lower()
    if v in {"tg", "telegram"}:
        return "tg"
    if v in {"wa", "whatsapp"}:
        return "wa"
    return v


def _iso_to_aware_utc(value: str) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _get_logged_in_account_id() -> Optional[str]:
    try:
        account_id = get_account_id_from_request()
        return (account_id or "").strip() or None
    except Exception:
        return None


@bp.get("/status")
def link_status():
    account_id = _get_logged_in_account_id()
    if not account_id:
        return _json_error("Unauthorized", 401)

    tg_rows = (
        sb.table("accounts")
        .select("id,provider,provider_user_id,updated_at")
        .eq("account_id", account_id)
        .eq("provider", "tg")
        .limit(1)
        .execute()
    )

    wa_rows = (
        sb.table("accounts")
        .select("id,provider,provider_user_id,updated_at")
        .eq("account_id", account_id)
        .eq("provider", "wa")
        .limit(1)
        .execute()
    )

    tg = (tg_rows.data or [None])[0]
    wa = (wa_rows.data or [None])[0]

    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "telegram": {
                "linked": bool(tg),
                "provider_user_id": (tg or {}).get("provider_user_id") if tg else None,
                "updated_at": (tg or {}).get("updated_at") if tg else None,
            },
            "whatsapp": {
                "linked": bool(wa),
                "provider_user_id": (wa or {}).get("provider_user_id") if wa else None,
                "updated_at": (wa or {}).get("updated_at") if wa else None,
            },
        }
    )


@bp.post("/generate")
def generate_link_code():
    """
    Website side.
    Uses the logged-in session/account instead of trusting a posted auth_user_id.

    Body:
    {
        "provider": "wa" | "tg"
    }
    """
    account_id = _get_logged_in_account_id()
    if not account_id:
        return _json_error("Unauthorized", 401)

    body = request.get_json(silent=True) or {}
    provider = _normalize_provider(body.get("provider") or "")

    if provider not in {"wa", "tg"}:
        return _json_error("Invalid provider", 400)

    code = generate_code()
    expires_at = _utcnow() + timedelta(minutes=TOKEN_EXPIRY_MINUTES)

    # Best-effort cleanup of old unused tokens for this account/provider
    try:
        sb.table("link_tokens").delete().eq("account_id", account_id).eq("provider", provider).eq("used", False).execute()
    except Exception:
        pass

    insert_payload = {
        "code": code,
        "account_id": account_id,
        "provider": provider,
        "expires_at": expires_at.isoformat(),
        "used": False,
        "created_at": _utcnow().isoformat(),
    }

    try:
        sb.table("link_tokens").insert(insert_payload).execute()
    except Exception as e:
        return _json_error("Failed to generate link code", 500, detail=repr(e))

    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "provider": provider,
            "code": code,
            "expires_in_minutes": TOKEN_EXPIRY_MINUTES,
            "expires_at": expires_at.isoformat(),
        }
    )


@bp.post("/consume")
def consume_link_code():
    """
    Chat side.

    Body:
    {
        "code": "<8-char>",
        "provider": "wa" | "tg",
        "provider_user_id": "<chat id>",
        "display_name": "<optional>"
    }
    """
    body = request.get_json(silent=True) or {}

    code = (body.get("code") or "").strip().upper()
    provider = _normalize_provider(body.get("provider") or "")
    provider_user_id = str(body.get("provider_user_id") or "").strip()
    display_name = (body.get("display_name") or "").strip() or None

    if not code or provider not in {"wa", "tg"} or not provider_user_id:
        return _json_error("Invalid request", 400)

    try:
        res = (
            sb.table("link_tokens")
            .select("*")
            .eq("code", code)
            .eq("provider", provider)
            .single()
            .execute()
        )
        token = res.data
    except Exception:
        token = None

    if not token:
        return _json_error("Invalid code", 404)

    if bool(token.get("used")):
        return _json_error("Code already used", 400)

    expires_at_raw = token.get("expires_at")
    if not expires_at_raw:
        return _json_error("Code invalid", 400)

    try:
        expires_at = _iso_to_aware_utc(expires_at_raw)
    except Exception:
        return _json_error("Code invalid", 400)

    if expires_at < _utcnow():
        return _json_error("Code expired", 400)

    account_id = (token.get("account_id") or "").strip()
    if not account_id:
        return _json_error("Code invalid", 400)

    upsert_payload = {
        "account_id": account_id,
        "provider": provider,
        "provider_user_id": provider_user_id,
        "updated_at": _utcnow().isoformat(),
    }

    if display_name:
        upsert_payload["display_name"] = display_name

    try:
        sb.table("accounts").upsert(upsert_payload).execute()
    except Exception as e:
        return _json_error("Failed to link account", 500, detail=repr(e))

    try:
        (
            sb.table("link_tokens")
            .update(
                {
                    "used": True,
                    "used_at": _utcnow().isoformat(),
                    "provider_user_id": provider_user_id,
                }
            )
            .eq("code", code)
            .execute()
        )
    except Exception as e:
        return _json_error("Link created but token finalization failed", 500, detail=repr(e))

    return jsonify(
        {
            "ok": True,
            "linked": True,
            "account_id": account_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
        }
    )
