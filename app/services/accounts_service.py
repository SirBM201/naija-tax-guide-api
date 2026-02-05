# app/services/accounts_service.py
from typing import Optional, Dict, Any
from ..core.supabase_client import supabase


def upsert_account(
    provider: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Expected Supabase table: accounts
      - id (uuid, pk)
      - provider (text)
      - provider_user_id (text)
      - display_name (text, nullable)
      - phone (text, nullable)
      - created_at (timestamptz)
      - updated_at (timestamptz)

    Unique constraint recommended on (provider, provider_user_id)
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if not provider or not provider_user_id:
        raise ValueError("provider and provider_user_id are required")

    db = supabase()

    # Try fetch
    got = (
        db.table("accounts")
        .select("*")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )

    if getattr(got, "data", None):
        row = got.data[0]

        # Optional update fields (non-destructive)
        updates: Dict[str, Any] = {}
        if display_name and (row.get("display_name") != display_name):
            updates["display_name"] = display_name
        if phone and (row.get("phone") != phone):
            updates["phone"] = phone

        if updates:
            upd = (
                db.table("accounts")
                .update(updates)
                .eq("id", row["id"])
                .execute()
            )
            if getattr(upd, "data", None):
                row = upd.data[0]

        return row

    # Insert
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

    if not getattr(ins, "data", None):
        raise RuntimeError("Failed to create account")

    return ins.data[0]
