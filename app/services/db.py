# app/services/db.py

"""
Compatibility layer for imports like:
  from ..services.db import supabase_admin

This codebase uses:
  from ..core.supabase_client import supabase

We expose:
- supabase_admin() -> returns the service-role Supabase client (from core.supabase_client)

Also includes:
- supabase_admin_client proxy for older code that does:
    from ..services.db import supabase_admin_client as supabase_admin
    supabase_admin.rpc(...)
or even mistakenly:
    from ..services.db import supabase_admin
    supabase_admin.rpc(...)
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

    Supports legacy patterns like:
        from ..services.db import supabase_admin_client as supabase_admin
        supabase_admin.rpc("fn", {...}).execute()

    Or even (old buggy usage):
        from ..services.db import supabase_admin
        supabase_admin.rpc("fn", {...}).execute()
    """
    def __getattr__(self, name: str) -> Any:
        return getattr(supabase_admin(), name)


# ✅ Use this in any legacy modules that expect "a client object"
supabase_admin_client = _SupabaseAdminProxy()

# ✅ Extra backwards-compat: if any old file does `from ..services.db import supabase_admin`
# and then calls `.rpc` on it, they will fail because supabase_admin is a function.
# So we also export a second name many devs accidentally used.
supabase_admin_proxy = supabase_admin_client
