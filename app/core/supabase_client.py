# app/core/supabase_client.py
"""
Central Supabase client factory for the backend.

Rules:
- Backend uses SERVICE ROLE key only
- Client created once (singleton)
- Safe for RPC/inserts/updates/webhooks (server-side only)
"""

from __future__ import annotations

from typing import Any, Optional
from supabase import create_client

from .config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

_client: Optional[Any] = None


def get_supabase() -> Any:
    global _client

    if _client is not None:
        return _client

    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not set")
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is not set")

    _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _client


# Backward-compatible import style:
#   from app.core.supabase_client import supabase
#   supabase.table("...").select("*").execute()
supabase = get_supabase()
