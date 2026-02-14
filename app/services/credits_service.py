# app/services/credits_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.core.supabase_client import supabase

# -----------------------------
# Config
# -----------------------------
DEFAULT_INITIAL_CREDITS = int((os.getenv("DEFAULT_INITIAL_CREDITS", "0") or "0").strip())

# Optional: if you want plan-based initial credits, define env like:
# PLAN_CREDITS_JSON='{"monthly":300,"quarterly":900,"yearly":3600,"free":0}'
# or PLAN_CREDITS_JSON='{"basic":300,"pro":600,"enterprise":2000}'
PLAN_CREDITS_JSON = (os.getenv("PLAN_CREDITS_JSON", "") or "").strip()


# -----------------------------
# Time helpers
# -----------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# -----------------------------
# Internal helpers
# -----------------------------
def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _plan_credit_map() -> Dict[str, int]:
    """
    Loads optional mapping from env PLAN_CREDITS_JSON.
    If not set or invalid, returns empty dict.
    """
    if not PLAN_CREDITS_JSON:
        return {}
    try:
        import json

        raw = json.loads(PLAN_CREDITS_JSON)
        if isinstance(raw, dict):
            out: Dict[str, int] = {}
            for k, v in raw.items():
                out[str(k).strip().lower()] = _safe_int(v, 0)
            return out
        return {}
    except Exception:
        return {}


def _get_balance_row(account_id: str) -> Optional[Dict[str, Any]]:
    try:
        res = (
            supabase.table("ai_credit_balances")
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        return rows[0] if rows else None
    except Exception:
        return None


def _read_balance_value(row: Dict[str, Any]) -> int:
    bal = row.get("balance")
    if bal is None:
        bal = row.get("credits")
    return _safe_int(bal, 0)


def _upsert_balance(account_id: str, new_balance: int) -> bool:
    """
    Upsert using update first; if missing row, insert.
    Handles both 'balance' and 'credits' column variants.
    """
    new_balance = _safe_int(new_balance, 0)

    # Try update (balance)
    try:
        supabase.table("ai_credit_balances").update(
            {"balance": new_balance, "updated_at": _iso(_now_utc())}
        ).eq("account_id", account_id).execute()
        return True
    except Exception:
        pass

    # Try update (credits)
    try:
        supabase.table("ai_credit_balances").update(
            {"credits": new_balance, "updated_at": _iso(_now_utc())}
        ).eq("account_id", account_id).execute()
        return True
    except Exception:
        pass

    # Try insert (balance)
    try:
        supabase.table("ai_credit_balances").insert(
            {"account_id": account_id, "balance": new_balance, "updated_at": _iso(_now_utc())}
        ).execute()
        return True
    except Exception:
        pass

    # Try insert (credits)
    try:
        supabase.table("ai_credit_balances").insert(
            {"account_id": account_id, "credits": new_balance, "updated_at": _iso(_now_utc())}
        ).execute()
        return True
    except Exception:
        return False


def _log_ledger_event(account_id: str, delta: int, reason: str, meta: Optional[Dict[str, Any]] = None) -> None:
    """
    Optional event log; best-effort only.
    """
    try:
        supabase.table("ai_credit_ledger").insert(
            {
                "account_id": account_id,
                "delta": _safe_int(delta, 0),
                "reason": (reason or "unknown")[:120],
                "meta": meta or {},
                "created_at": _iso(_now_utc()),
            }
        ).execute()
    except Exception:
        pass


# -----------------------------
# Public functions
# -----------------------------
def get_credit_balance(account_id: str) -> Dict[str, Any]:
    """
    Reads from: public.ai_credit_balances

    Returns:
      { ok: True, account_id, balance, source: "existing"|"created" }
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "no_account_id"}

    row = _get_balance_row(account_id)
    if row:
        return {"ok": True, "account_id": account_id, "balance": _read_balance_value(row), "source": "existing"}

    # Create if missing (best-effort)
    ok = _upsert_balance(account_id, DEFAULT_INITIAL_CREDITS)
    if ok:
        return {"ok": True, "account_id": account_id, "balance": DEFAULT_INITIAL_CREDITS, "source": "created"}

    return {"ok": False, "error": "failed_to_init_balance"}


def init_credits_for_plan(account_id: str, plan_code: Optional[str]) -> Dict[str, Any]:
    """
    Compatibility function required by your existing subscriptions_service.py.

    Behavior (safe & professional):
    - Ensures ai_credit_balances row exists.
    - If PLAN_CREDITS_JSON is set and plan_code matches, it TOPS UP to at least that amount
      (i.e. sets balance = max(current, plan_default)).
    - If no mapping, it does nothing beyond ensuring the row exists.

    Returns:
      { ok: True, balance, applied: bool, plan_code, rule }
    """
    account_id = (account_id or "").strip()
    plan = (plan_code or "").strip().lower()

    bal = get_credit_balance(account_id)
    if not bal.get("ok"):
        return bal

    current = _safe_int(bal.get("balance"), 0)

    mapping = _plan_credit_map()
    if not mapping or not plan or plan not in mapping:
        # No plan rule configured; keep current
        return {
            "ok": True,
            "account_id": account_id,
            "balance": current,
            "applied": False,
            "plan_code": plan_code,
            "rule": "no_plan_mapping",
        }

    target = _safe_int(mapping.get(plan), 0)
    if target <= 0:
        return {
            "ok": True,
            "account_id": account_id,
            "balance": current,
            "applied": False,
            "plan_code": plan_code,
            "rule": "plan_target_zero",
        }

    # Only increase to minimum target (avoid wiping user's earned credits)
    new_balance = current if current >= target else target
    if new_balance != current:
        if not _upsert_balance(account_id, new_balance):
            return {"ok": False, "error": "failed_to_apply_plan_credits", "balance": current}
        _log_ledger_event(account_id, new_balance - current, reason="plan_credit_init", meta={"plan_code": plan_code})
        return {
            "ok": True,
            "account_id": account_id,
            "balance": new_balance,
            "applied": True,
            "plan_code": plan_code,
            "rule": "set_min_balance_to_plan_target",
        }

    return {
        "ok": True,
        "account_id": account_id,
        "balance": current,
        "applied": False,
        "plan_code": plan_code,
        "rule": "already_at_or_above_target",
    }


def deduct_credits(account_id: str, amount: int, reason: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Safe-ish deduction:
      - ensure balance row exists
      - if insufficient -> fail
      - update balance
      - log ledger event (best effort)
    """
    amount = _safe_int(amount, 0)
    if amount <= 0:
        return {"ok": False, "error": "invalid_amount"}

    bal = get_credit_balance(account_id)
    if not bal.get("ok"):
        return bal

    current = _safe_int(bal.get("balance"), 0)
    if current < amount:
        return {"ok": False, "error": "insufficient_credits", "balance": current}

    new_balance = current - amount
    if not _upsert_balance(account_id, new_balance):
        return {"ok": False, "error": "failed_to_update_balance"}

    _log_ledger_event(account_id, -amount, reason=reason, meta=meta)
    return {"ok": True, "balance": new_balance}
