# app/services/db.py
"""
Compatibility layer for imports like:
  from app.services.db import supabase_admin

This codebase uses:
  from app.core.supabase_client import supabase

We expose:
- supabase_admin() -> returns the service-role Supabase client (from core.supabase_client)

Also includes:
- supabase_admin_client proxy for older code that does:
    from app.services.db import supabase_admin_client
    supabase_admin_client.rpc(...)

And ALSO supports the legacy pattern:
    from app.services.db import supabase_admin
    supabase_admin.rpc(...)
by making supabase_admin a function, and providing a proxy if needed.
"""

from __future__ import annotations

from typing import Any
from ..core.supabase_client import supabase


def supabase_admin() -> Any:
    """
    Return the Supabase client configured in core.supabase_client.
    This should be service-role on the server.
    """
    return supabase()


class _SupabaseAdminProxy:
    """
    Proxy that forwards attribute access to supabase_admin().

    Allows old code patterns like:
        from app.services.db import supabase_admin_client
        supabase_admin_client.rpc("fn", {...}).execute()
    """
    def __getattr__(self, name: str) -> Any:
        return getattr(supabase_admin(), name)


# Legacy-friendly "client object" form
supabase_admin_client = _SupabaseAdminProxy()
