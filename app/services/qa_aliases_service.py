from __future__ import annotations
from typing import Optional
from ..core.supabase_client import supabase

def find_canonical_by_alias(alias_key: str, lang: str) -> Optional[str]:
    if not alias_key or not lang:
        return None
    res = (
        supabase.table("qa_aliases")
        .select("canonical_key")
        .eq("alias_key", alias_key)
        .eq("lang", lang)
        .limit(1)
        .execute()
    )
    data = getattr(res, "data", None) or []
    if not data:
        return None
    return data[0].get("canonical_key")
