from typing import Optional
from app.db.supabase_client import supabase

def digits_only(s: str) -> str:
    return "".join(ch for ch in (s or "").strip() if ch.isdigit())

def normalize_provider(p: str) -> str:
    v = (p or "").strip().lower()
    if v in ("wa", "whatsapp"):
        return "wa"
    if v in ("tg", "telegram"):
        return "tg"
    return "web"

def normalize_provider_user_id(provider: str, provider_user_id: str) -> str:
    provider = normalize_provider(provider)
    uid = (provider_user_id or "").strip()
    if provider in ("wa", "web"):
        uid = digits_only(uid)
    return uid

def acct_key(acct_id: str) -> str:
    return f"acct:{acct_id}"

def ensure_account(provider: str, provider_user_id: str) -> str:
    """
    Ensures row exists in accounts, returns acct_key = acct:<uuid>

    accounts table expected:
      - id (uuid)
      - provider (text)
      - provider_user_id (text)
    """
    provider = normalize_provider(provider)
    uid = normalize_provider_user_id(provider, provider_user_id)
    if not uid:
        raise ValueError("provider_user_id required")

    r = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", uid)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return acct_key(str(rows[0]["id"]))

    ins = (
        supabase()
        .table("accounts")
        .insert({"provider": provider, "provider_user_id": uid})
        .execute()
    )
    data = getattr(ins, "data", None) or []
    if not data:
        # race-safe fallback
        r2 = (
            supabase()
            .table("accounts")
            .select("id")
            .eq("provider", provider)
            .eq("provider_user_id", uid)
            .limit(1)
            .execute()
        )
        rows2 = getattr(r2, "data", None) or []
        if rows2:
            return acct_key(str(rows2[0]["id"]))
        raise RuntimeError("Failed to create account")

    return acct_key(str(data[0]["id"]))
