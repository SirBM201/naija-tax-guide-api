# app/services/credits_service.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from app.core.supabase_client import supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# Your schema:
# public.ai_credit_balances: account_id (uuid), balance (int4), updated_at (timestamptz)
BAL_TABLE = "ai_credit_balances"
BAL_COL_ACCOUNT = "account_id"
BAL_COL_BALANCE = "balance"
BAL_COL_UPDATED = "updated_at"

# Your schema:
# public.plans: plan_code, ai_credits_total, ...
PLANS_TABLE = "plans"


def get_credit_balance(account_id: str) -> int:
    account_id = (account_id or "").strip()
    if not account_id:
        return 0

    res = (
        supabase.table(BAL_TABLE)
        .select(BAL_COL_BALANCE)
        .eq(BAL_COL_ACCOUNT, account_id)
        .limit(1)
        .execute()
    )
    rows = (res.data or []) if hasattr(res, "data") else []
    if not rows:
        return 0

    try:
        return int(rows[0].get(BAL_COL_BALANCE) or 0)
    except Exception:
        return 0


def _set_credit_balance(account_id: str, new_balance: int) -> None:
    supabase.table(BAL_TABLE).upsert(
        {
            BAL_COL_ACCOUNT: account_id,
            BAL_COL_BALANCE: int(new_balance),
            BAL_COL_UPDATED: _now_utc().isoformat().replace("+00:00", "Z"),
        },
        on_conflict=BAL_COL_ACCOUNT,
    ).execute()


def init_credits_for_plan(account_id: str, plan_code: str) -> Dict[str, Any]:
    """
    Called after a subscription is activated/changed.

    Behavior:
    - Looks up plans.ai_credits_total
    - Sets ai_credit_balances.balance = ai_credits_total (overwrite)
    """
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip().lower()

    if not account_id or not plan_code:
        return {"ok": False, "error": "missing account_id or plan_code"}

    pres = (
        supabase.table(PLANS_TABLE)
        .select("plan_code, ai_credits_total")
        .eq("plan_code", plan_code)
        .limit(1)
        .execute()
    )
    prows = (pres.data or []) if hasattr(pres, "data") else []
    if not prows:
        return {"ok": False, "error": f"unknown plan_code: {plan_code}"}

    total = int(prows[0].get("ai_credits_total") or 0)
    _set_credit_balance(account_id, total)

    return {"ok": True, "account_id": account_id, "plan_code": plan_code, "balance": total}
