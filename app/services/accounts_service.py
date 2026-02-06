from typing import Optional, Dict, Any
from app.core.supabase_client import supabase


def upsert_account_link(
    *,
    provider: str,
    provider_user_id: str,
    auth_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Ensures provider_user_id is linked to auth_user_id.
    Multi-channel supported: same auth_user_id can link multiple providers.
    Safety:
      - A provider_user_id cannot be linked to two different auth users.
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()
    auth_user_id = (auth_user_id or "").strip()

    if not provider or not provider_user_id or not auth_user_id:
        return {"ok": False, "error": "provider/provider_user_id/auth_user_id required"}

    # 1) Does this provider_user_id already exist?
    existing = (
        supabase()
        .table("accounts")
        .select("id, provider, provider_user_id, auth_user_id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )

    row = (existing.data or [None])[0]

    # 2) If already linked to a DIFFERENT auth_user_id => block
    if row and row.get("auth_user_id") and row.get("auth_user_id") != auth_user_id:
        return {
            "ok": False,
            "error": "This channel is already linked to another account.",
            "reason": "channel_already_linked",
        }

    payload = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "auth_user_id": auth_user_id,
    }
    if display_name is not None:
        payload["display_name"] = display_name
    if phone is not None:
        payload["phone"] = phone

    # 3) Upsert on (provider, provider_user_id)
    # IMPORTANT: Your DB should have a unique constraint on (provider, provider_user_id)
    res = (
        supabase()
        .table("accounts")
        .upsert(payload, on_conflict="provider,provider_user_id")
        .select("*")
        .execute()
    )

    saved = (res.data or [None])[0]
    if not saved:
        return {"ok": False, "error": "Failed to link channel"}

    return {"ok": True, "account": saved}
