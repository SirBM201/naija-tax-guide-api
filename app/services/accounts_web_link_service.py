# app/services/accounts_web_link_service.py
from __future__ import annotations

from typing import Optional, Dict, Any
from ..core.supabase_client import supabase

def find_account_by_phone(phone_e164: str) -> Optional[str]:
    resp = (
        supabase.table("accounts")
        .select("id")
        .eq("phone_e164", phone_e164)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        return None
    return rows[0]["id"]

def create_account_with_phone(phone_e164: str) -> str:
    resp = (
        supabase.table("accounts")
        .insert({"phone_e164": phone_e164})
        .select("id")
        .single()
        .execute()
    )
    return resp.data["id"]

def upsert_identity(account_id: str, provider: str, provider_user_id: str) -> None:
    # Make sure account_identities has a unique key like (provider, provider_user_id)
    supabase.table("account_identities").upsert(
        {
            "account_id": account_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
        },
        on_conflict="provider,provider_user_id",
    ).execute()

def get_or_create_account_for_web(contact: str) -> str:
    """
    For DEV OTP, we treat contact as phone_e164 (recommended).
    You can extend to email later (same flow).
    """
    account_id = find_account_by_phone(contact)
    if not account_id:
        account_id = create_account_with_phone(contact)

    # provider_user_id = contact is okay for web identity
    upsert_identity(account_id, "web", contact)
    return account_id
