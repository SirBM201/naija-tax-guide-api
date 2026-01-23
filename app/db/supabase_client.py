# app/db/supabase_client.py
import logging
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY

_supabase = None

def get_supabase():
    global _supabase
    if _supabase is not None:
        return _supabase

    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        logging.warning("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing. DB calls will fail.")
    _supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _supabase
