# app/services/db.py
"""
Compatibility layer for old imports:
  from ..services.db import supabase_admin

Your codebase already uses:
  from ..core.supabase_client import supabase

So this file simply exposes "supabase_admin" as an alias to "supabase()".

This fixes:
  ModuleNotFoundError: No module named 'app.services.db'
"""

from typing import Any
from ..core.supabase_client import supabase


def supabase_admin() -> Any:
    """
    Returns a Supabase client created using the service role key
    (as configured in core.supabase_client).
    """
    return supabase()
