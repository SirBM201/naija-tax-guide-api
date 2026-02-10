# app/services/referrals_service.py
from __future__ import annotations

from typing import Optional, Dict, Any
from ..core.supabase_client import supabase

# You can tune this later
REFERRAL_BONUS_KOBO = {
    "monthly": 30000,     # ₦300
    "quarterly": 80000,   # ₦800
    "yearly": 200000,     # ₦2000
}

def get_referrer(account_id: str) -> Optional[str]:
    db = supabase()
    res = db.table("referrals").select("referred_by").eq("account_id", account_id).limit(1).execute()
    if res.data and res.data[0].get("referred_by"):
        return str(res.data[0]["referred_by"])
    return None

def create_referral_earning(
    referred_account_id: str,
    plan_code: str,
) -> Dict[str, Any]:
    plan = (plan_code or "").strip().lower()
    if plan not in REFERRAL_BONUS_KOBO:
        return {"ok": False, "reason": "unsupported_plan"}

    referrer = get_referrer(referred_account_id)
    if not referrer:
        return {"ok": False, "reason": "no_referrer"}

    amount_kobo = int(REFERRAL_BONUS_KOBO[plan])

    db = supabase()
    try:
        db.table("referral_earnings").insert(
            {
                "referrer_account_id": referrer,
                "referred_account_id": referred_account_id,
                "plan_code": plan,
                "amount_kobo": amount_kobo,
                "status": "pending",
            }
        ).execute()
        return {"ok": True, "referrer_account_id": referrer, "amount_kobo": amount_kobo}
    except Exception as e:
        return {"ok": False, "reason": "insert_failed", "error": str(e)}
