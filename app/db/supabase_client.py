# app/db/supabase_client.py
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

_client = None

def supabase():
    global _client
    if _client is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
            raise RuntimeError("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY not set")
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _client
