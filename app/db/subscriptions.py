# app/db/subscriptions.py
from typing import Any, Dict, Optional
from app.db.supabase_rest import sb_get


def get_subscription_row(wa_phone: str) -> Optional[Dict[str, Any]]:
    rows = sb_get(
        "user_subscriptions",
        params={
            "select": "wa_phone,plan,status,expires_at,updated_at",
            "wa_phone": f"eq.{wa_phone}",
            "limit": "1",
        },
    )
    return rows[0] if rows else None


def get_plan_expiry_iso(wa_phone: str) -> Optional[str]:
    row = get_subscription_row(wa_phone)
    if not row:
        return None
    return row.get("expires_at")
