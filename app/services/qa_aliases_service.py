# app/services/qa_aliases_service.py
from __future__ import annotations
from typing import Optional
from ..core.supabase_client import supabase


def resolve_alias_to_canonical(*, alias_key: str, lang: str) -> Optional[str]:
    alias_key = (alias_key or "").strip()
    lang = (lang or "").strip().lower()
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
    return (data[0].get("canonical_key") or "").strip() or None


def upsert_alias(*, alias_key: str, lang: str, canonical_key: str) -> bool:
    alias_key = (alias_key or "").strip()
    canonical_key = (canonical_key or "").strip()
    lang = (lang or "").strip().lower()
    if not alias_key or not canonical_key or not lang:
        return False

    payload = {"alias_key": alias_key, "lang": lang, "canonical_key": canonical_key}
    supabase.table("qa_aliases").upsert(payload).execute()
    return True
