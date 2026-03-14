from __future__ import annotations

import os
from decimal import Decimal
from typing import Any, Dict, List, Optional

from app.core.supabase_client import supabase


# =========================================================
# INTERNAL HELPERS
# =========================================================

def _sb():
    return supabase() if callable(supabase) else supabase


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _to_decimal(value: Any, default: Decimal = Decimal("0")) -> Decimal:
    try:
        if value is None:
            return default
        return Decimal(str(value))
    except Exception:
        return default


def _rows(resp: Any) -> List[Dict[str, Any]]:
    if resp is None:
        return []
    data = getattr(resp, "data", None)
    return data if isinstance(data, list) else []


def _first(resp: Any) -> Optional[Dict[str, Any]]:
    rows = _rows(resp)
    return rows[0] if rows else None


# =========================================================
# ENV CONFIG
# =========================================================

def payout_enabled() -> bool:
    return _truthy(os.getenv("REFERRAL_PAYOUT_ENABLED") or "1")


def payout_provider() -> str:
    return (os.getenv("REFERRAL_PAYOUT_PROVIDER") or "paystack").strip().lower()


def payout_currency() -> str:
    return (os.getenv("REFERRAL_REWARD_CURRENCY") or "NGN").strip().upper()


def min_payout_amount() -> Decimal:
    return _to_decimal(os.getenv("REFERRAL_MIN_PAYOUT_AMOUNT") or "2000", Decimal("2000"))


def payout_auto_release() -> bool:
    return _truthy(os.getenv("REFERRAL_PAYOUT_AUTO_RELEASE") or "0")


# =========================================================
# PAYOUT ACCOUNT HELPERS
# =========================================================

def get_payout_account(account_id: str) -> Optional[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return None

    resp = (
        _sb()
        .table("referral_payout_accounts")
        .select("*")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    return _first(resp)


def upsert_payout_account(
    *,
    account_id: str,
    provider: str = "paystack",
    bank_code: str | None = None,
    bank_name: str | None = None,
    account_name: str | None = None,
    account_number_masked: str | None = None,
    recipient_code: str | None = None,
    currency: str | None = None,
    is_verified: bool = False,
) -> Dict[str, Any]:
    account_id = str(account_id or "").strip()
    if not account_id:
        raise ValueError("account_id is required")

    payload = {
        "account_id": account_id,
        "provider": (provider or payout_provider()).strip().lower(),
        "bank_code": bank_code,
        "bank_name": bank_name,
        "account_name": account_name,
        "account_number_masked": account_number_masked,
        "recipient_code": recipient_code,
        "currency": (currency or payout_currency()).strip().upper(),
        "is_verified": bool(is_verified),
    }

    existing = get_payout_account(account_id)
    if existing:
        resp = (
            _sb()
            .table("referral_payout_accounts")
            .update(payload)
            .eq("account_id", account_id)
            .execute()
        )
        row = _first(resp)
        if row:
            return row
        again = get_payout_account(account_id)
        if again:
            return again
        raise RuntimeError("Failed to update payout account")

    resp = _sb().table("referral_payout_accounts").insert(payload).execute()
    row = _first(resp)
    if row:
        return row

    again = get_payout_account(account_id)
    if again:
        return again

    raise RuntimeError("Failed to create payout account")


# =========================================================
# PAYOUT ROW HELPERS
# =========================================================

def list_payout_rows_for_account(account_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return []

    limit = max(1, min(_safe_int(limit, 100), 500))
    resp = (
        _sb()
        .table("referral_payouts")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return _rows(resp)


def get_pending_or_processing_payout(account_id: str) -> Optional[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return None

    for status in ("pending", "processing"):
        resp = (
            _sb()
            .table("referral_payouts")
            .select("*")
            .eq("account_id", account_id)
            .eq("status", status)
            .limit(1)
            .execute()
        )
        row = _first(resp)
        if row:
            return row
    return None


def create_payout_row(
    *,
    account_id: str,
    amount: Decimal,
    currency: str | None = None,
    provider: str | None = None,
    provider_reference: str | None = None,
    provider_transfer_code: str | None = None,
    status: str = "pending",
) -> Dict[str, Any]:
    account_id = str(account_id or "").strip()
    if not account_id:
        raise ValueError("account_id is required")
    if amount <= 0:
        raise ValueError("amount must be greater than zero")

    payload = {
        "account_id": account_id,
        "amount": str(amount),
        "currency": (currency or payout_currency()).strip().upper(),
        "provider": (provider or payout_provider()).strip().lower(),
        "provider_reference": provider_reference,
        "provider_transfer_code": provider_transfer_code,
        "status": status,
        "requested_at": None,
        "processed_at": None,
        "paid_at": None,
        "failed_at": None,
        "failure_reason": None,
    }

    resp = _sb().table("referral_payouts").insert(payload).execute()
    row = _first(resp)
    if row:
        return row
    raise RuntimeError("Failed to create payout row")


def update_payout_status(
    *,
    payout_id: str,
    status: str,
    provider_reference: str | None = None,
    provider_transfer_code: str | None = None,
    failure_reason: str | None = None,
) -> Optional[Dict[str, Any]]:
    payout_id = str(payout_id or "").strip()
    if not payout_id:
        raise ValueError("payout_id is required")

    patch: Dict[str, Any] = {
        "status": status,
        "provider_reference": provider_reference,
        "provider_transfer_code": provider_transfer_code,
        "failure_reason": failure_reason,
    }

    if status == "processing":
        patch["processed_at"] = "now()"
    elif status == "paid":
        patch["paid_at"] = "now()"
    elif status == "failed":
        patch["failed_at"] = "now()"

    resp = _sb().table("referral_payouts").update(patch).eq("id", payout_id).execute()
    return _first(resp)


# =========================================================
# BALANCE / ELIGIBILITY
# =========================================================

def list_approved_rewards_for_account(account_id: str) -> List[Dict[str, Any]]:
    account_id = str(account_id or "").strip()
    if not account_id:
        return []

    resp = (
        _sb()
        .table("referral_rewards")
        .select("*")
        .eq("account_id", account_id)
        .eq("status", "approved")
        .order("created_at", desc=False)
        .execute()
    )
    return _rows(resp)


def approved_balance_for_account(account_id: str) -> Decimal:
    rows = list_approved_rewards_for_account(account_id)
    total = Decimal("0")
    for row in rows:
        total += _to_decimal(row.get("reward_amount"))
    return total


def payout_eligibility(account_id: str) -> Dict[str, Any]:
    account_id = str(account_id or "").strip()
    if not account_id:
        raise ValueError("account_id is required")

    if not payout_enabled():
        return {
            "ok": True,
            "eligible": False,
            "reason": "payout_disabled",
        }

    payout_account = get_payout_account(account_id)
    if not payout_account:
        return {
            "ok": True,
            "eligible": False,
            "reason": "missing_payout_account",
        }

    if not bool(payout_account.get("is_verified")):
        return {
            "ok": True,
            "eligible": False,
            "reason": "payout_account_not_verified",
            "payout_account": payout_account,
        }

    pending_or_processing = get_pending_or_processing_payout(account_id)
    if pending_or_processing:
        return {
            "ok": True,
            "eligible": False,
            "reason": "existing_pending_or_processing_payout",
            "payout": pending_or_processing,
        }

    balance = approved_balance_for_account(account_id)
    minimum = min_payout_amount()

    if balance < minimum:
        return {
            "ok": True,
            "eligible": False,
            "reason": "below_minimum_payout_amount",
            "approved_balance": str(balance),
            "minimum_required": str(minimum),
        }

    return {
        "ok": True,
        "eligible": True,
        "approved_balance": str(balance),
        "minimum_required": str(minimum),
        "currency": payout_currency(),
        "payout_account": payout_account,
    }


# =========================================================
# REQUEST PAYOUT (MANUAL REQUEST RECORD)
# =========================================================

def request_payout(account_id: str) -> Dict[str, Any]:
    account_id = str(account_id or "").strip()
    if not account_id:
        raise ValueError("account_id is required")

    eligibility = payout_eligibility(account_id)
    if not eligibility.get("eligible"):
        return {
            "ok": True,
            "requested": False,
            "eligibility": eligibility,
        }

    balance = _to_decimal(eligibility.get("approved_balance"), Decimal("0"))
    payout_row = create_payout_row(
        account_id=account_id,
        amount=balance,
        currency=payout_currency(),
        provider=payout_provider(),
        status="pending",
    )

    return {
        "ok": True,
        "requested": True,
        "eligibility": eligibility,
        "payout": payout_row,
    }
