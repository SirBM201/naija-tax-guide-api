# app/services/db.py
"""
Compatibility layer for imports like:
  from ..services.db import supabase_admin

This codebase uses:
  from ..core.supabase_client import supabase

We expose:
- supabase_admin() -> returns the service-role Supabase client (from core.supabase_client)

Also includes:
- a backwards-compatible "supabase_admin_client" proxy for older code that does:
    from ..services.db import supabase_admin
    supabase_admin.rpc(...)

If any old code imports supabase_admin as a CLIENT (not as a function),
it will still work by calling through the proxy.
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
    This allows older code patterns like:

        from ..services.db import supabase_admin
        supabase_admin.rpc("fn", {...}).execute()

    Even though supabase_admin is now a function.
    """
    def __getattr__(self, name: str) -> Any:
        return getattr(supabase_admin(), name)


# Optional: if any legacy modules expect supabase_admin to be a client object.
supabase_admin_client = _SupabaseAdminProxy()
