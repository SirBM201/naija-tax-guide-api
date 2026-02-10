# app/services/credits_service.py
from __future__ import annotations

from typing import Any, Dict, Optional

from app.core.supabase_client import supabase


def init_credits_for_plan(*, account_id: str, plan_code: str) -> Dict[str, Any]:
    """
    Resets credits to plan's ai_credits_total.
    Called on subscription activation/renewal.
    Uses DB RPC for consistency.
    """
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip()

    if not account_id or not plan_code:
        return {"ok": False, "error": "missing_account_id_or_plan_code"}

    try:
        res = (
            supabase()
            .rpc("init_ai_credits_for_plan", {"p_account_id": account_id, "p_plan_code": plan_code})
            .execute()
        )
        # Supabase returns in res.data
        data = res.data
        if isinstance(data, dict):
            return data
        if isinstance(data, list) and data:
            return data[0]
        return {"ok": True, "raw": data}
    except Exception as e:
        return {"ok": False, "error": f"RPC error: {str(e)}"}


def consume_one_credit(
    *,
    account_id: str,
    plan_code: Optional[str],
    reason: str = "ask",
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Atomically consumes 1 credit and enforces daily cap in Postgres.
    Returns:
      { ok: True, balance, used_today, daily_limit } OR
      { ok: False, error: 'out_of_credits'|'daily_limit_reached'|... }
    """
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip() if plan_code else ""

    if not account_id:
        return {"ok": False, "error": "missing_account_id"}

    payload = {
        "p_account_id": account_id,
        "p_plan_code": plan_code,
        "p_reason": reason,
        "p_meta": meta or {},
    }

    try:
        res = supabase().rpc("consume_ai_credit", payload).execute()
        data = res.data
        if isinstance(data, dict):
            return data
        if isinstance(data, list) and data:
            return data[0]
        return {"ok": True, "raw": data}
    except Exception as e:
        return {"ok": False, "error": f"RPC error: {str(e)}"}
