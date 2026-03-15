from __future__ import annotations

import hashlib
import os
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

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


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json_error(message: str, status: int = 400, **extra: Any):
    payload: Dict[str, Any] = {"ok": False, "error": message}
    if extra:
        payload.update(extra)
    return jsonify(payload), status


def _normalize_provider(raw: str) -> str:
    v = (raw or "").strip().lower()
    if v in {"tg", "telegram"}:
        return "tg"
    if v in {"wa", "whatsapp"}:
        return "wa"
    return v


def _generate_code(length: int = TOKEN_LENGTH) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _safe_iso_to_dt(value: Any) -> Optional[datetime]:
    try:
        if not value:
            return None
        text = str(value).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _get_logged_in_account_id() -> Tuple[Optional[str], Dict[str, Any]]:
    try:
        account_id, dbg = get_account_id_from_request(request)
        account_id = (account_id or "").strip() or None
        return account_id, dbg if isinstance(dbg, dict) else {}
    except Exception as e:
        return None, {"ok": False, "error": "auth_resolution_failed", "detail": repr(e)}


def _find_account_row_for_provider(account_id: str, provider: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            sb.table("accounts")
            .select(
                "id,account_id,auth_user_id,provider,provider_user_id,email,display_name,phone,phone_e164,updated_at,created_at"
            )
            .eq("account_id", account_id)
            .eq("provider", provider)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        return rows[0] if rows else None
    except Exception:
        return None


def _find_account_row_by_provider_user(provider: str, provider_user_id: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            sb.table("accounts")
            .select(
                "id,account_id,auth_user_id,provider,provider_user_id,email,display_name,phone,phone_e164,updated_at,created_at"
            )
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        return rows[0] if rows else None
    except Exception:
        return None


@bp.get("/status")
def link_status():
    account_id, auth_dbg = _get_logged_in_account_id()
    if not account_id:
        return _json_error("Unauthorized", 401, auth=auth_dbg)

    tg_row = _find_account_row_for_provider(account_id, "tg")
    wa_row = _find_account_row_for_provider(account_id, "wa")

    return jsonify(
        {
            "ok": True,
            "account_id": account_id,
            "telegram": {
                "linked": bool(tg_row),
                "provider_user_id": (tg_row or {}).get("provider_user_id") if tg_row else None,
                "display_name": (tg_row or {}).get("display_name") if tg_row else None,
                "updated_at": (tg_row or {}).get("updated_at") if tg_row else None,
            },
            "whatsapp": {
                "linked": bool(wa_row),
                "provider_user_id": (wa_row or {}).get("provider_user_id") if wa_row else None,
                "display_name": (wa_row or {}).get("display_name") if wa_row else None,
                "updated_at": (wa_row or {}).get("updated_at") if wa_row else None,
            },
        }
    )


@bp.post("/generate")
def generate_link_code():
    """
    Website side.

    Body:
    {
        "provider": "wa" | "tg"
    }

    Important:
    - Uses authenticated web session identity from get_account_id_from_request(...)
    - Stores canonical account id into link_tokens.auth_user_id because that is the live schema
    """
    account_id, auth_dbg = _get_logged_in_account_id()
    if not account_id:
        return _json_error("Unauthorized", 401, auth=auth_dbg)

    body = request.get_json(silent=True) or {}
    provider = _normalize_provider(body.get("provider") or "")

    if provider not in {"wa", "tg"}:
        return _json_error("Invalid provider", 400)

    code = _generate_code()
    code_hash = _sha256_hex(code)
    now = _utcnow()
    expires_at = now + timedelta(minutes=TOKEN_EXPIRY_MINUTES)

    try:
        (
            sb.table("link_tokens")
            .update(
                {
                    "used_at": now.isoformat(),
                }
            )
            .eq("auth_user_id", account_id)
            .eq("provider", provider)
            .is_("used_at", "null")
            .execute()
        )
    except Exception:
        pass

    insert_payload = {
        "id": str(uuid.uuid4()),
        "auth_user_id": account_id,
        "provider": provider,
        "code": code,
        "code_hash": code_hash,
        "expires_at": expires_at.isoformat(),
        "used_at": None,
        "provider_user_id": None,
        "created_at": now.isoformat(),
    }

    try:
        sb.table("link_tokens").insert(insert_payload).execute()
    except Exception as e:
        return _json_error(
            "Failed to generate link code",
            500,
            detail=repr(e),
            account_id=account_id,
            provider=provider,
        )

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
        "display_name": "<optional>",
        "phone": "<optional>",
        "phone_e164": "<optional>"
    }
    """
    body = request.get_json(silent=True) or {}

    code = (body.get("code") or "").strip().upper()
    provider = _normalize_provider(body.get("provider") or "")
    provider_user_id = str(body.get("provider_user_id") or "").strip()
    display_name = (body.get("display_name") or "").strip() or None
    phone = (body.get("phone") or "").strip() or None
    phone_e164 = (body.get("phone_e164") or "").strip() or None

    if not code or provider not in {"wa", "tg"} or not provider_user_id:
        return _json_error("Invalid request", 400)

    token: Optional[Dict[str, Any]] = None

    try:
        res = (
            sb.table("link_tokens")
            .select("*")
            .eq("provider", provider)
            .eq("code", code)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        token = rows[0] if rows else None
    except Exception:
        token = None

    if not token:
        try:
            code_hash = _sha256_hex(code)
            res = (
                sb.table("link_tokens")
                .select("*")
                .eq("provider", provider)
                .eq("code_hash", code_hash)
                .limit(1)
                .execute()
            )
            rows = res.data or []
            token = rows[0] if rows else None
        except Exception:
            token = None

    if not token:
        return _json_error("Invalid code", 404)

    if token.get("used_at"):
        return _json_error("Code already used", 400)

    expires_at = _safe_iso_to_dt(token.get("expires_at"))
    if not expires_at:
        return _json_error("Code invalid", 400)

    if expires_at <= _utcnow():
        return _json_error("Code expired", 400)

    account_id = str(token.get("auth_user_id") or "").strip()
    if not account_id:
        return _json_error("Code invalid", 400)

    existing_same_account_provider = _find_account_row_for_provider(account_id, provider)
    existing_same_provider_user = _find_account_row_by_provider_user(provider, provider_user_id)

    now = _utcnow().isoformat()

    row_payload: Dict[str, Any] = {
        "account_id": account_id,
        "auth_user_id": account_id,
        "provider": provider,
        "provider_user_id": provider_user_id,
        "updated_at": now,
    }

    if display_name:
        row_payload["display_name"] = display_name
    if phone:
        row_payload["phone"] = phone
    if phone_e164:
        row_payload["phone_e164"] = phone_e164

    try:
        if existing_same_account_provider and existing_same_account_provider.get("id"):
            (
                sb.table("accounts")
                .update(row_payload)
                .eq("id", existing_same_account_provider["id"])
                .execute()
            )
        elif existing_same_provider_user and existing_same_provider_user.get("id"):
            (
                sb.table("accounts")
                .update(row_payload)
                .eq("id", existing_same_provider_user["id"])
                .execute()
            )
        else:
            insert_row = {
                "id": str(uuid.uuid4()),
                "created_at": now,
                **row_payload,
            }
            sb.table("accounts").insert(insert_row).execute()
    except Exception as e:
        return _json_error(
            "Failed to link account",
            500,
            detail=repr(e),
            account_id=account_id,
            provider=provider,
            provider_user_id=provider_user_id,
        )

    try:
        (
            sb.table("link_tokens")
            .update(
                {
                    "used_at": now,
                    "provider_user_id": provider_user_id,
                }
            )
            .eq("id", token["id"])
            .execute()
        )
    except Exception as e:
        return _json_error(
            "Link created but token finalization failed",
            500,
            detail=repr(e),
            account_id=account_id,
            provider=provider,
            provider_user_id=provider_user_id,
        )

    return jsonify(
        {
            "ok": True,
            "linked": True,
            "account_id": account_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
        }
    )
    
