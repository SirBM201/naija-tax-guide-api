# app/core/identity.py
import logging
from typing import Optional, Dict, Any

from app.db.supabase_client import sb


def acct_key(acct_id: str) -> str:
    """
    Store subscription identity as: 'acct:<uuid>'
    """
    return f"acct:{acct_id}"


def resolve_acct_id(provider: str, provider_user_id: str) -> str:
    """
    Finds or creates an account for (provider, provider_user_id).
    Returns acct_id (uuid string).
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg", "web"):
        raise ValueError("provider must be one of: wa, tg, web")
    if not provider_user_id:
        raise ValueError("provider_user_id is required")

    client = sb()

    # lookup
    r = (
        client.table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return str(rows[0]["id"])

    # create
    ins = (
        client.table("accounts")
        .insert({"provider": provider, "provider_user_id": provider_user_id})
        .execute()
    )
    data = getattr(ins, "data", None) or []
    if not data:
        raise RuntimeError("Failed to create account")
    return str(data[0]["id"])


def get_subscription_by_acct_key(acct_key_str: str) -> Optional[Dict[str, Any]]:
    """
    Reads subscription row from user_subscriptions using wa_phone = 'acct:<uuid>'.
    (We keep column name wa_phone for now to avoid risky refactor.)
    """
    try:
        client = sb()
        r = (
            client.table("user_subscriptions")
            .select("*")
            .eq("wa_phone", acct_key_str)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None
