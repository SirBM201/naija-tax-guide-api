# app/services/credits_service.py
from __future__ import annotations

"""
CREDITS SERVICE (CANONICAL + FAILURE EXPOSERS)

This module MUST NOT crash your boot due to missing exports.

Why you're seeing:
  ImportError: cannot import name 'check_credit_balance' from app.services.credits_service

Because some route/service imports `check_credit_balance`, but the file only defines
`get_credit_balance`. This file provides BOTH APIs:

- get_credit_balance(account_id) -> int
- check_credit_balance(account_id, cost=1) -> dict with ok/root_cause/fix

✅ Canonical identity:
  - account_id always means accounts.account_id (NOT accounts.id)

Schema assumed:
  public.ai_credit_balances:
    - account_id (uuid)  PRIMARY/UNIQUE
    - balance (int4)
    - updated_at (timestamptz)
"""

from datetime import datetime, timezone
from typing import Any, Dict

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _now_utc().isoformat().replace("+00:00", "Z")


def _clip(s: str, n: int = 240) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


BAL_TABLE = "ai_credit_balances"
BAL_COL_ACCOUNT = "account_id"
BAL_COL_BALANCE = "balance"
BAL_COL_UPDATED = "updated_at"

PLANS_TABLE = "plans"


def get_credit_balance(account_id: str) -> int:
    """Return current AI credit balance (int). Never throws: returns 0 on any failure."""
    account_id = (account_id or "").strip()
    if not account_id:
        return 0

    try:
        res = (
            _sb()
            .table(BAL_TABLE)
            .select(BAL_COL_BALANCE)
            .eq(BAL_COL_ACCOUNT, account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return 0
        return _as_int(rows[0].get(BAL_COL_BALANCE), 0)
    except Exception:
        return 0


def check_credit_balance(account_id: str, cost: int = 1) -> Dict[str, Any]:
    """Boot-safe, debuggable credit pre-check."""
    account_id = (account_id or "").strip()
    cost = _as_int(cost, 1)
    if cost < 1:
        cost = 1

    if not account_id:
        return {
            "ok": False,
            "error": "account_id_required",
            "root_cause": "account_id was empty",
            "fix": "Pass canonical accounts.account_id into the request/session.",
        }

    try:
        res = (
            _sb()
            .table(BAL_TABLE)
            .select(f"{BAL_COL_BALANCE},{BAL_COL_UPDATED}")
            .eq(BAL_COL_ACCOUNT, account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        balance = _as_int((rows[0].get(BAL_COL_BALANCE) if rows else 0), 0)
    except Exception as e:
        return {
            "ok": False,
            "error": "credits_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": f"Verify {BAL_TABLE} exists, RLS allows read, and account_id is correct.",
            "details": {"table": BAL_TABLE, "account_id": account_id},
        }

    remaining = balance - cost
    if remaining < 0:
        return {
            "ok": False,
            "error": "insufficient_credits",
            "balance": balance,
            "cost": cost,
            "remaining": max(0, remaining),
            "root_cause": "AI credits are below required cost for this request.",
            "fix": "Top up credits / activate a plan / reduce usage. (In dev: manually set ai_credit_balances.balance).",
        }

    return {"ok": True, "balance": balance, "cost": cost, "remaining": remaining}


def _set_credit_balance(account_id: str, new_balance: int) -> None:
    """Internal helper: set/overwrite balance (upsert)."""
    _sb().table(BAL_TABLE).upsert(
        {
            BAL_COL_ACCOUNT: account_id,
            BAL_COL_BALANCE: int(new_balance),
            BAL_COL_UPDATED: _iso_now(),
        },
        on_conflict=BAL_COL_ACCOUNT,
    ).execute()


def init_credits_for_plan(account_id: str, plan_code: str) -> Dict[str, Any]:
    """Called after a subscription is activated/changed. Overwrites balance to plan's ai_credits_total."""
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip().lower()

    if not account_id or not plan_code:
        return {
            "ok": False,
            "error": "missing_account_or_plan",
            "root_cause": "account_id or plan_code empty",
            "fix": "Pass valid account_id and plan_code.",
        }

    try:
        pres = (
            _sb()
            .table(PLANS_TABLE)
            .select("plan_code, ai_credits_total")
            .eq("plan_code", plan_code)
            .limit(1)
            .execute()
        )
        prows = getattr(pres, "data", None) or []
        if not prows:
            return {
                "ok": False,
                "error": "unknown_plan_code",
                "root_cause": f"plans.plan_code not found for '{plan_code}'",
                "fix": "Insert the plan into plans table or pass a valid plan_code.",
            }
        total = _as_int(prows[0].get("ai_credits_total"), 0)
    except Exception as e:
        return {
            "ok": False,
            "error": "plan_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check plans table, RLS, and the ai_credits_total column.",
        }

    try:
        _set_credit_balance(account_id, total)
    except Exception as e:
        return {
            "ok": False,
            "error": "credit_set_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check ai_credit_balances RLS allows upsert/update for service key.",
        }

    return {"ok": True, "account_id": account_id, "plan_code": plan_code, "balance": total}


# Backward-compat aliases (to prevent boot crashes)
def credits_balance(account_id: str) -> int:
    return get_credit_balance(account_id)
