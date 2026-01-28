import logging
from app.db.supabase_client import supabase

log = logging.getLogger(__name__)


def resolve_acct_id(provider: str, provider_user_id: str) -> str:
    """
    Resolve or create a canonical acct_id for any channel identity.
    provider: wa | tg | web
    provider_user_id: phone / chat_id / session_id
    """
    provider = (provider or "").strip()
    provider_user_id = (provider_user_id or "").strip()

    if not provider or not provider_user_id:
        raise ValueError("provider and provider_user_id are required")

    sb = supabase()

    # 1) Look up existing identity
    q = (
        sb.table("account_identities")
        .select("acct_id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )

    if q.data:
        return q.data[0]["acct_id"]

    # 2) Create guest account
    acct = sb.table("accounts").insert({"status": "guest"}).execute()
    acct_id = acct.data[0]["acct_id"]

    # 3) Link identity
    sb.table("account_identities").insert({
        "acct_id": acct_id,
        "provider": provider,
        "provider_user_id": provider_user_id,
    }).execute()

    log.info("Created guest acct %s for %s:%s", acct_id, provider, provider_user_id)
    return acct_id
