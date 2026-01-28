import uuid
import logging
from app.db.supabase_client import supabase

log = logging.getLogger(__name__)


def resolve_acct_id(provider: str, provider_user_id: str) -> str:
    """
    Returns existing acct_id or creates a new guest account.
    """
    provider = provider.strip()
    provider_user_id = provider_user_id.strip()

    # 1) lookup
    r = (
        supabase()
        .table("account_identities")
        .select("acct_id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return rows[0]["acct_id"]

    # 2) create guest account
    acct_id = str(uuid.uuid4())

    supabase().table("accounts").insert({
        "acct_id": acct_id,
        "status": "guest",
    }).execute()

    supabase().table("account_identities").insert({
        "provider": provider,
        "provider_user_id": provider_user_id,
        "acct_id": acct_id,
    }).execute()

    log.info("Created guest acct_id=%s for %s:%s", acct_id, provider, provider_user_id)
    return acct_id
