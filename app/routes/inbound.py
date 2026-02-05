def _consume_link(provider: str, code: str, provider_user_id: str):
    provider = (provider or "").strip().lower()
    code = (code or "").strip()
    provider_user_id = (provider_user_id or "").strip()

    if not provider or not code or not provider_user_id:
        return None

    db = supabase_admin()
    res = db.rpc(
        "consume_link_token",
        {"p_provider": provider, "p_code": code, "p_provider_user_id": provider_user_id},
    ).execute()

    return res.data[0] if getattr(res, "data", None) else None


def _maybe_link_from_message(provider: str, text: str, provider_user_id: str):
    txt = (text or "").strip()
    if not txt.lower().startswith("link "):
        return None

    code = txt[5:].strip()
    if not code:
        return None

    return _consume_link(provider, code, provider_user_id)
