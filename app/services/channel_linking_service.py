# app/services/channel_linking_service.py
from __future__ import annotations

import re
from typing import Optional, Dict, Any

from app.core.supabase_client import supabase
from app.services.accounts_service import upsert_account_link

# 6–12 alphanumeric (accept lowercase too, normalize to upper)
CODE_RE = re.compile(r"\b([A-Z0-9]{6,12})\b", re.IGNORECASE)


def extract_code(text: str) -> Optional[str]:
    """
    Extracts the first 6–12 alphanumeric token from user text.
    Works with:
      - "ABC12345"
      - "/start ABC12345"
      - "my code is abc12345"
    """
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
    """
    1) consume_link_token RPC
    2) link channel to auth_user_id in accounts table (safe guard against overwrite)
    """
    provider = (provider or "").strip().lower()
    code = (code or "").strip().upper()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg"):
        return {"ok": False, "error": "provider must be wa or tg"}
    if not code:
        return {"ok": False, "error": "code required"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id required"}

    # 1) consume via RPC
    try:
        res = supabase().rpc(
            "consume_link_token",
            {"p_provider": provider, "p_code": code, "p_provider_user_id": provider_user_id},
        ).execute()
    except Exception as e:
        return {"ok": False, "error": f"RPC error: {str(e)}"}

    row = (res.data or [None])[0]
    if not row or not row.get("ok"):
        return {"ok": False, "error": "invalid_or_expired_code"}

    auth_user_id = row.get("auth_user_id")
    if not auth_user_id:
        return {"ok": False, "error": "consume_link_token_missing_auth_user_id"}

    # 2) link account mapping safely
    link = upsert_account_link(
        provider=provider,
        provider_user_id=provider_user_id,
        auth_user_id=auth_user_id,
        display_name=display_name,
        phone=phone,
    )
    if not link.get("ok"):
        return {"ok": False, "error": link.get("error") or "failed_to_link", "reason": link.get("reason")}

    return {
        "ok": True,
        "provider": provider,
        "provider_user_id": provider_user_id,
        "auth_user_id": auth_user_id,
        "token_id": row.get("token_id"),
        "expires_at": row.get("expires_at"),
        "account": link.get("account"),
    }
