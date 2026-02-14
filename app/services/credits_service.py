# app/services/credits_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.core.supabase_client import supabase

DEFAULT_INITIAL_CREDITS = int((os.getenv("DEFAULT_INITIAL_CREDITS", "0") or "0").strip())


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_credit_balance(account_id: str) -> Dict[str, Any]:
    """
    Reads from: public.ai_credit_balances
    Expected columns (typical):
      - account_id (uuid)
      - balance (int) OR credits (int) (we handle both)
      - updated_at (timestamptz optional)

    Returns:
      { ok: True, account_id, balance, source: "existing"|"created" }
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "no_account_id"}

    # 1) Try read
    try:
        res = (
            supabase.table("ai_credit_balances")
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        row = rows[0] if rows else None
    except Exception:
        row = None

    if row:
        bal = row.get("balance")
        if bal is None:
            bal = row.get("credits")
        try:
            bal_int = int(bal or 0)
        except Exception:
            bal_int = 0
        return {"ok": True, "account_id": account_id, "balance": bal_int, "source": "existing"}

    # 2) Create row if missing (best-effort)
    payload = {"account_id": account_id, "balance": DEFAULT_INITIAL_CREDITS, "updated_at": _iso(_now_utc())}
    try:
        supabase.table("ai_credit_balances").insert(payload).execute()
        return {"ok": True, "account_id": account_id, "balance": DEFAULT_INITIAL_CREDITS, "source": "created"}
    except Exception:
        # If your table uses "credits" instead of "balance"
        payload2 = {"account_id": account_id, "credits": DEFAULT_INITIAL_CREDITS, "updated_at": _iso(_now_utc())}
        try:
            supabase.table("ai_credit_balances").insert(payload2).execute()
            return {"ok": True, "account_id": account_id, "balance": DEFAULT_INITIAL_CREDITS, "source": "created"}
        except Exception:
            return {"ok": False, "error": "failed_to_init_balance"}


def _update_balance(account_id: str, new_balance: int) -> bool:
    try:
        supabase.table("ai_credit_balances").update(
            {"balance": int(new_balance), "updated_at": _iso(_now_utc())}
        ).eq("account_id", account_id).execute()
        return True
    except Exception:
        # fallback if column name is "credits"
        try:
            supabase.table("ai_credit_balances").update(
                {"credits": int(new_balance), "updated_at": _iso(_now_utc())}
            ).eq("account_id", account_id).execute()
            return True
        except Exception:
            return False


def _log_ledger_event(account_id: str, delta: int, reason: str, meta: Optional[Dict[str, Any]] = None) -> None:
    """
    Optional ledger event log.
    Uses ai_credit_ledger if available.
    If your table name differs, ignore this function or rename accordingly.
    """
    try:
        supabase.table("ai_credit_ledger").insert(
            {
                "account_id": account_id,
                "delta": int(delta),
                "reason": (reason or "unknown")[:120],
                "meta": meta or {},
                "created_at": _iso(_now_utc()),
            }
        ).execute()
    except Exception:
        # silently ignore if ledger table/columns differ
        pass


def deduct_credits(account_id: str, amount: int, reason: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Safe-ish deduction:
      - read current balance
      - if insufficient -> fail
      - update balance
      - log ledger event (best effort)
    """
    amount = int(amount or 0)
    if amount <= 0:
        return {"ok": False, "error": "invalid_amount"}

    bal = get_credit_balance(account_id)
    if not bal.get("ok"):
        return bal

    current = int(bal.get("balance") or 0)
    if current < amount:
        return {"ok": False, "error": "insufficient_credits", "balance": current}

    new_balance = current - amount
    if not _update_balance(account_id, new_balance):
        return {"ok": False, "error": "failed_to_update_balance"}

    _log_ledger_event(account_id, -amount, reason=reason, meta=meta)
    return {"ok": True, "balance": new_balance}
