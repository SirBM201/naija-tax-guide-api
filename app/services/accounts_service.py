# app/services/accounts_service.py

from app.core.supabase_client import supabase


def get_or_create_account(provider, provider_user_id):
    """
    Fetch account or auto-create if missing
    """

    db = supabase()

    # 1️⃣ Try fetch
    res = (
        db.table("accounts")
        .select("*")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .execute()
    )

    if res.data:
        return res.data[0]

    # 2️⃣ Auto-create
    insert = (
        db.table("accounts")
        .insert(
            {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "plan": "free",
                "plan_expiry": None,
            }
        )
        .execute()
    )

    if insert.data:
        return insert.data[0]

    return None
