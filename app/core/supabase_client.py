# app/core/supabase_client.py
from __future__ import annotations

import os
from typing import Optional

from supabase import create_client, Client


_SUPABASE: Optional[Client] = None


def get_supabase() -> Client:
    """
    Returns a singleton Supabase Client.
    IMPORTANT:
      - This must return a Client object (has .table()).
      - If you accidentally export a function named `supabase`,
        importing it as `supabase` will cause "'function' object has no attribute 'table'".
    """
    global _SUPABASE

    if _SUPABASE is not None:
        return _SUPABASE

    url = (os.getenv("SUPABASE_URL") or "").strip()
    key = (
        (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
        or (os.getenv("SUPABASE_ANON_KEY") or "").strip()
    )

    if not url or not key:
        raise RuntimeError(
            "Supabase not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (recommended) "
            "or SUPABASE_ANON_KEY."
        )

    _SUPABASE = create_client(url, key)
    return _SUPABASE
