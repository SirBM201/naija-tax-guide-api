from __future__ import annotations

from typing import Optional, Dict, Any
import re

from app.core.supabase_client import supabase
from app.services.accounts_service import upsert_account_link

CODE_RE = re.compile(r"^[A-Z0-9]{6,12}$")


def extract_code(text: str) -> Optional[str]:
    """
    Accepts:
      - "ABC123"
      - "/start ABC123"
      - "code: ABC123"
      - "Here is my code ABC123"
    Returns uppercase code if found.
    """
    if not text:
        return None
    t = text.strip()

    # Telegram "/start CODE"
    if t.lower().startswith("/start"):
        parts = t.split()
        if len(parts) >= 2:
            cand = parts[1].strip().upper()
            if CODE_RE.match(cand):
                return cand

    # Exact code
    cand = t.strip().upper()
    if CODE_RE.match(cand):
        return cand

    # Search within text for a code-like token
    tokens = re.findall(r"[A-Za-z0-9]{6,12}", t)
    for tok in tokens:
        cand2 = tok.upper()
        if CODE_RE.match(cand2):
            return cand2

    return None


def consume_and_link(
    *,
    provider: str,
    code: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Calls Supabase RPC consume_link_token() then links accounts row.
    Returns:
      { ok: True, auth_user_id, token_id, expires_at }
      or { ok: False, error/message }
    """
    provider = (provider or "").strip().lower()
    code = (code or "").strip().upper()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg"):
        return {"ok": False, "error": "provider must be wa or tg"}
    if not code or not CODE_RE.match(code):
        return {"ok": False, "error": "Invalid code format"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id required"}

    try:
        res = supabase().rpc(
            "consume_link_token",
            {
                "p_provider": provider,
                "p_code": code,
                "p_provider_user_id": provider_user_id,
            },
        ).execute()
    except Exception as e:
        return {"ok": False, "error": f"RPC error: {str(e)}"}

    row = (res.data or [None])[0]
    if not row or not row.get("ok"):
        return {"ok": False, "message": "Invalid or expired code"}

    auth_user_id = row.get("auth_user_id")
    if not auth_user_id:
        return {"ok": False, "error": "consume_link_token returned no auth_user_id"}

    link_res = upsert_account_link(
        provider=provider,
        provider_user_id=provider_user_id,
        auth_user_id=auth_user_id,
        display_name=display_name,
        phone=phone,
    )
    if not link_res.get("ok"):
        return {"ok": False, "error": link_res.get("error") or "Failed to link account"}

    return {
        "ok": True,
        "provider": provider,
        "auth_user_id": auth_user_id,
        "token_id": row.get("token_id"),
        "expires_at": row.get("expires_at"),
    }
