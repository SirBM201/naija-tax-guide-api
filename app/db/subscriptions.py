# app/db/subscriptions.py
from typing import Optional
from app.db.supabase_client import get_supabase

def get_plan_expiry_iso(wa_phone: str) -> Optional[str]:
    sb = get_supabase()
    phone = (wa_phone or "").strip()
    if not phone:
        return None

    # Your screenshot shows "user_subscriptions" exists.
    resp = (
        sb.table("user_subscriptions")
        .select("expires_at,status,wa_phone")
        .eq("wa_phone", phone)
        .limit(1)
        .execute()
    )
    rows = getattr(resp, "data", None) or []
    if not rows:
        return None

    row = rows[0]
    return row.get("expires_at") or None
