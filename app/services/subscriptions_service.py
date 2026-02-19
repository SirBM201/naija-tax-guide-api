# app/services/subscriptions_service.py
from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timedelta, timezone

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat((value or "").replace("Z", "+00:00"))
    except Exception:
        return None


# -------------------------------------------------
# Status Lookup
# -------------------------------------------------

def get_subscription_status(
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Returns subscription state for frontend/billing guard.
    """

    if not account_id:
        return {
            "account_id": None,
            "active": False,
            "expires_at": None,
            "grace_until": None,
            "plan_code": None,
            "reason": "missing_account_id",
            "state": "none",
        }

    try:
        res = (
            _sb()
            .table("subscriptions")
            .select("account_id,plan_code,status,expires_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )

        rows = getattr(res, "data", None) or []
        if not rows:
            return {
                "account_id": account_id,
                "active": False,
                "expires_at": None,
                "grace_until": None,
                "plan_code": None,
                "reason": "no_subscription",
                "state": "none",
            }

        row = rows[0]
        exp = _parse_iso(row.get("expires_at"))
        now = _now_utc()

        if exp and exp > now and row.get("status") == "active":
            return {
                "account_id": account_id,
                "active": True,
                "expires_at": row.get("expires_at"),
                "grace_until": None,
                "plan_code": row.get("plan_code"),
                "reason": "active",
                "state": "active",
            }

        return {
            "account_id": account_id,
            "active": False,
            "expires_at": row.get("expires_at"),
            "grace_until": None,
            "plan_code": row.get("plan_code"),
            "reason": "expired_or_inactive",
            "state": "expired",
        }

    except Exception:
        return {
            "account_id": account_id,
            "active": False,
            "expires_at": None,
            "grace_until": None,
            "plan_code": None,
            "reason": "status_lookup_failed",
            "state": "none",
        }


# -------------------------------------------------
# Core Activation Logic
# -------------------------------------------------

def _compute_expiry(plan_code: str) -> str:
    plan = get_plan(plan_code)
    if not plan:
        raise ValueError("invalid_plan")

    duration = int(plan.get("duration_days") or 0)
    if duration <= 0:
        raise ValueError("invalid_plan_duration")

    expires = _now_utc() + timedelta(days=duration)
    return _iso(expires)


# -------------------------------------------------
# Auto Activation (Paystack / webhook)
# -------------------------------------------------

def activate_subscription_now(
    account_id: str,
    plan_code: str,
    status: str = "active",
) -> Dict[str, Any]:

    expires_at = _compute_expiry(plan_code)

    row = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": status,
        "expires_at": expires_at,
        "updated_at": _iso(_now_utc()),
    }

    res = (
        _sb()
        .table("subscriptions")
        .upsert(row, on_conflict="account_id")
        .execute()
    )

    data = getattr(res, "data", None) or []
    return data[0] if data else row


# -------------------------------------------------
# Manual Activation (Admin Override)
# -------------------------------------------------

def manual_activate_subscription(
    account_id: str,
    plan_code: str,
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Admin manual activation.
    Used for:
      - comp access
      - migration users
      - failed webhook recovery
    """

    if not expires_at:
        expires_at = _compute_expiry(plan_code)

    row = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": "active",
        "expires_at": expires_at,
        "updated_at": _iso(_now_utc()),
    }

    res = (
        _sb()
        .table("subscriptions")
        .upsert(row, on_conflict="account_id")
        .execute()
    )

    data = getattr(res, "data", None) or []
    return data[0] if data else row


# -------------------------------------------------
# Extend Subscription
# -------------------------------------------------

def extend_subscription(account_id: str, extra_days: int) -> Dict[str, Any]:

    res = (
        _sb()
        .table("subscriptions")
        .select("*")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )

    rows = getattr(res, "data", None) or []
    if not rows:
        raise ValueError("subscription_not_found")

    row = rows[0]
    current_exp = _parse_iso(row.get("expires_at")) or _now_utc()

    new_exp = current_exp + timedelta(days=extra_days)

    update = {
        "expires_at": _iso(new_exp),
        "updated_at": _iso(_now_utc()),
    }

    _sb().table("subscriptions").update(update).eq(
        "account_id", account_id
    ).execute()

    return {
        "account_id": account_id,
        "expires_at": update["expires_at"],
        "extended_days": extra_days,
    }


# -------------------------------------------------
# Cancel Subscription
# -------------------------------------------------

def cancel_subscription(account_id: str) -> Dict[str, Any]:

    update = {
        "status": "cancelled",
        "updated_at": _iso(_now_utc()),
    }

    _sb().table("subscriptions").update(update).eq(
        "account_id", account_id
    ).execute()

    return {
        "account_id": account_id,
        "cancelled": True,
    }
