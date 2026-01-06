from datetime import datetime, timezone
from .supabase_db import get_supabase

def get_cached_answer(normalized_key: str):
    sb = get_supabase()
    res = sb.table("qa_cache").select("*").eq("normalized_question", normalized_key).limit(1).execute()
    rows = res.data or []
    return rows[0] if rows else None

def upsert_cached_answer(normalized_key: str, answer: str, tags=None):
    sb = get_supabase()
    payload = {
        "normalized_question": normalized_key,
        "answer": answer,
        "tags": tags or [],
        "last_used_at": datetime.now(timezone.utc).isoformat(),
    }
    # Insert or update by unique key
    sb.table("qa_cache").upsert(payload, on_conflict="normalized_question").execute()

def increment_cache_use(normalized_key: str):
    sb = get_supabase()
    # fetch current use_count then update
    res = sb.table("qa_cache").select("use_count").eq("normalized_question", normalized_key).limit(1).execute()
    rows = res.data or []
    if not rows:
        return
    use_count = int(rows[0].get("use_count") or 0) + 1
    sb.table("qa_cache").update({
        "use_count": use_count,
        "last_used_at": datetime.now(timezone.utc).isoformat(),
    }).eq("normalized_question", normalized_key).execute()
