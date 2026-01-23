# app/db/ledger.py
from app.db.supabase_client import get_supabase
from app.core.utils import iso, now_utc

def ledger_add(wa_phone: str, delta: int, reason: str) -> None:
    sb = get_supabase()
    sb.table("ai_credit_wallet").insert({
        "wa_phone": wa_phone,
        "delta": int(delta),
        "reason": str(reason),
        "created_at": iso(now_utc())
    }).execute()
