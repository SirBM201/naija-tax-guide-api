from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from app.core.supabase_client import supabase
from app.services.accounts_service import upsert_account_link

# 8 chars, NON-ambiguous: 23456789 + A-HJ-NP-Z (no I, O)
CODE_RE = re.compile(r"\b([2-9A-HJ-NP-Z]{8})\b", re.IGNORECASE)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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


def extract_code(text: str) -> Optional[str]:
    t = (text or "").strip()
    if not t:
        return None
    m = CODE_RE.search(t)
    if not m:
        return None
    return (m.group(1) or "").strip().upper()


def consume_and_link(
    *,
    provider: str,
    code: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    provider = (provider or "").strip().lower()
    code = (code or "").strip().upper()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg", "msgr", "ig", "email"):
        return {"ok": False, "error": "provider_not_supported"}
    if not code:
        return {"ok": False, "error": "code_required"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id_required"}

    sb = supabase()

    token = None

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
        except Exception as e:
            return {"ok": False, "error": f"token_lookup_error:{str(e)}"}

    if not token:
        return {"ok": False, "error": "invalid_or_expired_code"}

    if token.get("used_at"):
        return {"ok": False, "error": "invalid_or_expired_code"}

    expires_at = _safe_iso_to_dt(token.get("expires_at"))
    if not expires_at:
        return {"ok": False, "error": "invalid_or_expired_code"}

    if expires_at <= _utcnow():
        return {"ok": False, "error": "invalid_or_expired_code"}

    auth_user_id = str(token.get("auth_user_id") or "").strip()
    if not auth_user_id:
        return {"ok": False, "error": "consume_missing_auth_user_id"}

    link = upsert_account_link(
        provider=provider,
        provider_user_id=provider_user_id,
        auth_user_id=auth_user_id,
        display_name=display_name,
        phone=phone,
    )
    if not link.get("ok"):
        return {
            "ok": False,
            "error": link.get("error") or "failed_to_link",
            "reason": link.get("reason"),
        }

    now = _utcnow().isoformat()

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
        return {"ok": False, "error": f"token_finalize_error:{str(e)}"}

    return {
        "ok": True,
        "provider": provider,
        "provider_user_id": provider_user_id,
        "auth_user_id": auth_user_id,
        "token_id": token.get("id"),
        "expires_at": token.get("expires_at"),
        "account": link.get("account"),
    }
