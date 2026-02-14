# app/services/credits_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# Tables
PLANS_TABLE = (os.getenv("PLANS_TABLE", "plans") or "plans").strip()
BAL_TABLE = (os.getenv("AI_CREDIT_BALANCES_TABLE", "ai_credit_balances") or "ai_credit_balances").strip()
EV_TABLE = (os.getenv("AI_CREDIT_EVENTS_TABLE", "ai_credit_events") or "ai_credit_events").strip()

# Plans columns
PLANS_COL_CODE = (os.getenv("PLANS_COL_CODE", "plan_code") or "plan_code").strip()
PLANS_COL_CREDITS = (os.getenv("PLANS_COL_CREDITS", "ai_credits_total") or "ai_credits_total").strip()

# Balance columns (your screenshot confirms: balance, updated_at)
BAL_COL_ACCOUNT_ID = (os.getenv("AI_CREDIT_BALANCES_COL_ACCOUNT_ID", "account_id") or "account_id").strip()
BAL_COL_BALANCE = (os.getenv("AI_CREDIT_BALANCES_COL_BALANCE", "balance") or "balance").strip()
BAL_COL_UPDATED_AT = (os.getenv("AI_CREDIT_BALANCES_COL_UPDATED_AT", "updated_at") or "updated_at").strip()

# Event columns (best-effort; will not crash if table differs)
EV_COL_ACCOUNT_ID = (os.getenv("AI_CREDIT_EVENTS_COL_ACCOUNT_ID", "account_id") or "account_id").strip()
EV_COL_EVENT_TYPE = (os.getenv("AI_CREDIT_EVENTS_COL_EVENT_TYPE", "event_type") or "event_type").strip()
EV_COL_AMOUNT = (os.getenv("AI_CREDIT_EVENTS_COL_AMOUNT", "amount") or "amount").strip()
EV_COL_META = (os.getenv("AI_CREDIT_EVENTS_COL_META", "meta") or "meta").strip()
EV_COL_CREATED_AT = (os.getenv("AI_CREDIT_EVENTS_COL_CREATED_AT", "created_at") or "created_at").strip()


def get_plan_credits(plan_code: str) -> Tuple[int, Optional[str]]:
    plan_code = (plan_code or "").strip()
    if not plan_code:
        return 0, "Missing plan_code"

    try:
        res = (
            supabase.table(PLANS_TABLE)
            .select(PLANS_COL_CREDITS)
            .eq(PLANS_COL_CODE, plan_code)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return 0, f"Plan not found: {plan_code}"

        return int(rows[0].get(PLANS_COL_CREDITS) or 0), None
    except Exception as e:
        return 0, f"Failed to read plan credits: {e}"


def get_credit_balance(account_id: str) -> Tuple[int, Optional[str]]:
    account_id = (account_id or "").strip()
    if not account_id:
        return 0, "Missing account_id"

    try:
        res = (
            supabase.table(BAL_TABLE)
            .select(BAL_COL_BALANCE)
            .eq(BAL_COL_ACCOUNT_ID, account_id)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return 0, None
        return int(rows[0].get(BAL_COL_BALANCE) or 0), None
    except Exception as e:
        return 0, f"Failed to read credit balance: {e}"


def set_credit_balance(account_id: str, new_balance: int, meta: Optional[Dict[str, Any]] = None) -> Tuple[bool, Optional[str]]:
    account_id = (account_id or "").strip()
    if not account_id:
        return False, "Missing account_id"

    try:
        payload = {
            BAL_COL_ACCOUNT_ID: account_id,
            BAL_COL_BALANCE: int(new_balance),
            BAL_COL_UPDATED_AT: _iso(_now_utc()),
        }
        supabase.table(BAL_TABLE).upsert(payload).execute()

        if meta is not None:
            _log_event_best_effort(account_id, "set_balance", int(new_balance), meta)

        return True, None
    except Exception as e:
        return False, f"Failed to set credit balance: {e}"


def ensure_credit_row(account_id: str) -> Tuple[bool, Optional[str]]:
    """
    Makes sure a balance row exists (0) so other code never breaks.
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return False, "Missing account_id"

    try:
        res = (
            supabase.table(BAL_TABLE)
            .select(BAL_COL_ACCOUNT_ID)
            .eq(BAL_COL_ACCOUNT_ID, account_id)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if rows:
            return True, None

        payload = {
            BAL_COL_ACCOUNT_ID: account_id,
            BAL_COL_BALANCE: 0,
            BAL_COL_UPDATED_AT: _iso(_now_utc()),
        }
        supabase.table(BAL_TABLE).insert(payload).execute()
        return True, None
    except Exception as e:
        return False, f"Failed to ensure credit row: {e}"


def init_credits_for_plan(account_id: str, plan_code: str) -> Tuple[bool, Optional[str], int]:
    """
    Seeds user credits on subscription activation/change.
    Overwrites balance to the plan's ai_credits_total.
    """
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip()

    if not account_id:
        return False, "Missing account_id", 0
    if not plan_code:
        return False, "Missing plan_code", 0

    credits, err = get_plan_credits(plan_code)
    if err:
        return False, err, 0

    ok, err2 = set_credit_balance(
        account_id,
        credits,
        meta={"plan_code": plan_code, "source": "subscription_activation"},
    )
    if not ok:
        return False, err2, 0

    return True, None, credits


def _log_event_best_effort(account_id: str, event_type: str, amount: int, meta: Dict[str, Any]) -> None:
    try:
        payload = {
            EV_COL_ACCOUNT_ID: account_id,
            EV_COL_EVENT_TYPE: (event_type or "").strip(),
            EV_COL_AMOUNT: int(amount),
            EV_COL_META: meta or {},
            EV_COL_CREATED_AT: _iso(_now_utc()),
        }
        supabase.table(EV_TABLE).insert(payload).execute()
    except Exception:
        pass
