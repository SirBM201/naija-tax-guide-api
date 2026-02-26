# app/services/accounts_web_link_service.py
from __future__ import annotations

from typing import Optional
from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def find_account_by_phone(phone_e164: str) -> Optional[str]:
    resp = (
        _sb()
        .table("accounts")
        .select("id,account_id")
        .eq("phone_e164", phone_e164)
        .limit(1)
        .execute()
    )
    rows = resp.data or []
    if not rows:
        return None
    row = rows[0] or {}
    return (row.get("account_id") or row.get("id"))


def create_account_with_phone(phone_e164: str) -> str:
    resp = (
        _sb()
        .table("accounts")
        .insert({"phone_e164": phone_e164})
        .select("id,account_id")
        .single()
        .execute()
    )
    row = resp.data or {}
    gid = (row.get("account_id") or row.get("id"))
    if not gid:
        raise RuntimeError("accounts insert returned no id/account_id (schema issue)")
    return str(gid)


def upsert_identity(account_id: str, provider: str, provider_user_id: str) -> None:
    _sb().table("account_identities").upsert(
        {
            "account_id": account_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
        },
        on_conflict="provider,provider_user_id",
    ).execute()


def get_or_create_account_for_web(contact: str) -> str:
    """
    Returns GLOBAL account id (accounts.account_id preferred).
    Failure exposer: raises if db returns no identifiers.
    """
    account_id = find_account_by_phone(contact)
    if not account_id:
        account_id = create_account_with_phone(contact)

    upsert_identity(account_id, "web", contact)
    return account_id
