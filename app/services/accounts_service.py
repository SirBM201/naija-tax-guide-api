# app/services/accounts_service.py
from typing import Optional, Dict, Any
from ..core.supabase_client import supabase


def upsert_account(
    provider: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    db = supabase()

    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    # normalize provider used in DB
    if provider == "whatsapp":
        provider = "wa"

    # Try fetch
    got = (
        db.table("accounts")
        .select("*")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )

    if got.data:
        row = got.data[0]
        updates = {}

        if display_name and (row.get("display_name") != display_name):
            updates["display_name"] = display_name
        if phone and (row.get("phone") != phone):
            updates["phone"] = phone

        if updates:
            upd = db.table("accounts").update(updates).eq("id", row["id"]).execute()
            if upd.data:
                row = upd.data[0]
        return row

    ins = (
        db.table("accounts")
        .insert(
            {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "display_name": display_name,
                "phone": phone,
            }
        )
        .execute()
    )
    return ins.data[0]
