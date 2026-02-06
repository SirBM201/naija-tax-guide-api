from __future__ import annotations

from typing import Optional, Dict, Any
from datetime import datetime, timezone

from app.core.supabase_client import supabase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def upsert_account(
    *,
    provider: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates or updates an account row WITHOUT auth_user_id (pre-link state).
    Used when a message arrives before linking.
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg"):
        return {"ok": False, "error": "provider must be wa or tg"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id required"}

    payload = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "display_name": display_name,
        "phone": phone,
        "updated_at": _now_iso(),
    }

    try:
        # NOTE: requires a UNIQUE constraint on (provider, provider_user_id)
        res = (
            supabase()
            .table("accounts")
            .upsert(payload, on_conflict="provider,provider_user_id")
            .select("*")
            .execute()
        )
    except Exception as e:
        return {"ok": False, "error": f"DB error: {str(e)}"}

    row = (res.data or [None])[0]
    return {"ok": True, "account": row}


def upsert_account_link(
    *,
    provider: str,
    provider_user_id: str,
    auth_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Upserts an account row AND binds it to auth_user_id (linked state).
    Called after consume_link_token succeeds.
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()
    auth_user_id = (auth_user_id or "").strip()

    if provider not in ("wa", "tg"):
        return {"ok": False, "error": "provider must be wa or tg"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id required"}
    if not auth_user_id:
        return {"ok": False, "error": "auth_user_id required"}

    payload = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "auth_user_id": auth_user_id,
        "display_name": display_name,
        "phone": phone,
        "updated_at": _now_iso(),
    }

    try:
        # NOTE: requires a UNIQUE constraint on (provider, provider_user_id)
        res = (
            supabase()
            .table("accounts")
            .upsert(payload, on_conflict="provider,provider_user_id")
            .select("*")
            .execute()
        )
    except Exception as e:
        return {"ok": False, "error": f"DB error: {str(e)}"}

    row = (res.data or [None])[0]
    return {"ok": True, "account": row}


def lookup_account(
    *,
    provider: str,
    provider_user_id: str,
) -> Dict[str, Any]:
    """
    Returns mapping from (provider, provider_user_id) -> auth_user_id (if linked)
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg"):
        return {"ok": False, "error": "provider must be wa or tg"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id required"}

    try:
        res = (
            supabase()
            .table("accounts")
            .select("provider,provider_user_id,auth_user_id,display_name,phone,updated_at,created_at")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return {"ok": False, "error": f"DB error: {str(e)}"}

    row = (res.data or [None])[0]
    if not row:
        return {"ok": True, "found": False, "linked": False, "account": None}

    auth_user_id = row.get("auth_user_id")
    return {
        "ok": True,
        "found": True,
        "linked": bool(auth_user_id),
        "auth_user_id": auth_user_id,
        "account": row,
    }
