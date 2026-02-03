# app/core/supabase_client.py

"""
Central Supabase client factory for the backend.

Rules:
- Backend ALWAYS uses SERVICE ROLE key
- Client is created once (singleton)
- Safe for RPC, inserts, updates, webhooks
- Used by:
    - services/db.py (supabase_admin)
    - subscriptions_service
    - inbound routes
"""

from __future__ import annotations

from typing import Any
from supabase import create_client
from .config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

_client: Any | None = None


def supabase() -> Any:
    """
    Returns a singleton Supabase client using SERVICE ROLE key.

    This MUST only be used on the server.
    Never expose this to frontend code.
    """
    global _client

    if _client is not None:
        return _client

    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not set")

    if not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY is not set")

    _client = create_client(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY,
    )

    return _client
