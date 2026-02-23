# app/services/subscriptions_service.py
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from ..core.supabase_client import supabase
from .subscription_status_service import get_subscription_status as _get_status


SUBSCRIPTIONS_TABLE = (os.getenv("SUBSCRIPTIONS_TABLE", "") or "").strip() or "subscriptions"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _default_expiry_for_plan(plan_code: str) -> Optional[datetime]:
    """
    Conservative defaults for admin test activation.
    You can override by sending expires_at in the request body.
    """
    p = (plan_code or "").strip().lower()
    now = _now_utc()

    if p == "monthly":
        return now + timedelta(days=30)
    if p == "quarterly":
        return now + timedelta(days=90)
    if p == "yearly":
        return now + timedelta(days=365)
    if p == "trial":
        return now + timedelta(days=7)

    # manual/unknown -> no expiry unless caller provides
    return None


def get_subscription_status(account_id: str) -> Dict[str, Any]:
    # Single source for subscription state computation
    return _get_status(account_id)


def activate_subscription_now(
    *,
    user_id: str,
    plan_code: str = "manual",
    expires_at_iso: Optional[str] = None,
    status: str = "active",
) -> Dict[str, Any]:
    """
    Admin-only helper: create/update a subscription row for the given user/account.

    Writes to SUBSCRIPTIONS_TABLE (default: 'subscriptions') using:
      account_id, plan_code, status, expires_at, grace_until, trial_until
    """
    account_id = (user_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "missing_account_id"}

    plan_code_norm = (plan_code or "manual").strip().lower()
    status_norm = (status or "active").strip().lower()

    # expiry
    if expires_at_iso:
        expires_at = expires_at_iso
    else:
        exp_dt = _default_expiry_for_plan(plan_code_norm)
        expires_at = _iso(exp_dt)

    # for trial, also set trial_until
    trial_until = None
    if plan_code_norm == "trial":
        trial_until = expires_at or _iso(_now_utc() + timedelta(days=7))

    payload: Dict[str, Any] = {
        "account_id": account_id,
        "plan_code": plan_code_norm,
        "status": status_norm,
        "expires_at": expires_at,
        "trial_until": trial_until,
        # grace_until optional: you can add later if you want
    }

    try:
        db = supabase()  # ✅ FIX: supabase() returns the client
        # Requires UNIQUE constraint on account_id (we added it in SQL)
        res = (
            db.table(SUBSCRIPTIONS_TABLE)
            .upsert(payload, on_conflict="account_id")
            .execute()
        )
        data = getattr(res, "data", None) or []
        row = data[0] if data else None
        return {"ok": True, "row": row, "table": SUBSCRIPTIONS_TABLE}
    except Exception as e:
        return {"ok": False, "error": "db_insert_failed", "message": f"{e.__class__.__name__}: {str(e)[:240]}"}
