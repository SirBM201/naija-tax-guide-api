# app/db/ledger.py
from typing import Optional
from datetime import datetime, timezone

from app.db.supabase_rest import sb_get, sb_post, sb_patch


def ledger_get_balance(wa_phone: str) -> int:
    rows = sb_get(
        "ledger",
        params={
            "select": "wa_phone,balance,updated_at",
            "wa_phone": f"eq.{wa_phone}",
            "limit": "1",
        },
    )
    if not rows:
        return 0
    return int(rows[0].get("balance") or 0)


def ledger_add(wa_phone: str, delta: int, reason: str) -> None:
    """
    Updates a single-row ledger per user (wa_phone).
    Expected table: ledger(wa_phone primary key, balance int, updated_at timestamptz, last_reason text)
    """
    rows = sb_get(
        "ledger",
        params={
            "select": "wa_phone,balance",
            "wa_phone": f"eq.{wa_phone}",
            "limit": "1",
        },
    )
    now = datetime.now(timezone.utc).isoformat()
    if not rows:
        sb_post("ledger", {"wa_phone": wa_phone, "balance": delta, "updated_at": now, "last_reason": reason})
        return

    bal = int(rows[0].get("balance") or 0)
    sb_patch(
        "ledger",
        {"balance": bal + delta, "updated_at": now, "last_reason": reason},
        params={"wa_phone": f"eq.{wa_phone}"},
    )


def ledger_ensure_monthly_topup(wa_phone: str, monthly_amount: int) -> None:
    """
    Simple auto-topup: if user has no ledger row, create with monthly_amount.
    If row exists and balance is negative/low, do nothing automatically here.
    You can extend later to reset monthly based on month boundary.
    """
    rows = sb_get(
        "ledger",
        params={
            "select": "wa_phone,balance",
            "wa_phone": f"eq.{wa_phone}",
            "limit": "1",
        },
    )
    if not rows:
        ledger_add(wa_phone, monthly_amount, "monthly_topup")
