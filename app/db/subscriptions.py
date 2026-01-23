# app/db/subscriptions.py
from typing import Optional
from app.core.utils import parse_iso_dt, iso
from app.db.supabase_client import supabase

# user_subscriptions: wa_phone, plan, status, expires_at, updated_at ...

def get_plan_expiry_iso(wa_phone: str) -> Optional[str]:
    if not wa_phone:
        return None

    q = (
        supabase()
        .table("user_subscriptions")
        .select("expires_at,status")
        .eq("wa_phone", wa_phone)
        .limit(1)
        .execute()
    )
    rows = (q.data or [])
    if not rows:
        return None

    row = rows[0]
    if (row.get("status") or "").lower() not in ("active", "paid", "enabled"):
        return None

    dt = parse_iso_dt(row.get("expires_at"))
    return iso(dt) if dt else None

def is_subscribed(wa_phone: str) -> bool:
    return bool(get_plan_expiry_iso(wa_phone))
