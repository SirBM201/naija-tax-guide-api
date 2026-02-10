# app/services/db.py
from __future__ import annotations

from typing import Any, Optional
from ..core.supabase_client import supabase


def supabase_admin() -> Any:
    return supabase()


class _SupabaseAdminProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(supabase_admin(), name)


# legacy compatibility
supabase_admin_client = _SupabaseAdminProxy()


def rpc_safe(fn_name: str, params: dict) -> tuple[bool, Optional[Any], str]:
    """
    Try RPC call. If it doesn't exist, return ok=False with reason.
    This prevents wasting time on missing RPCs.
    """
    sb = supabase_admin()
    try:
        res = sb.rpc(fn_name, params).execute()
        return True, res.data, ""
    except Exception as e:
        msg = str(e)
        # common "function not found" surface
        if "does not exist" in msg.lower() or "pgrst" in msg.lower():
            return False, None, msg
        return False, None, msg
