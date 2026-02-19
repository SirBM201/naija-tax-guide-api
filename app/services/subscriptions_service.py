# app/services/subscriptions_service.py
from __future__ import annotations

from typing import Any, Dict, Optional
from datetime import datetime, timedelta, timezone

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_subscription_status(
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Returns a frontend-safe status object.
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
        expires_at = row.get("expires_at")
        status = (row.get("status") or "").lower()

        # Best-effort parse expiry
        exp_dt = None
        try:
            exp_dt = datetime.fromisoformat((expires_at or "").replace("Z", "+00:00"))
        except Exception:
            exp_dt = None

        now = _now_utc()

        if status == "active" and exp_dt and exp_dt > now:
            return {
                "account_id": account_id,
                "active": True,
                "expires_at": expires_at,
                "grace_until": None,
                "plan_code": row.get("plan_code"),
                "reason": "active",
                "state": "active",
            }

        return {
            "account_id": account_id,
            "active": False,
            "expires_at": expires_at,
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


def activate_subscription_now(account_id: str, plan_code: str, status: str = "active") -> Dict[str, Any]:
    """
    Sets subscription for account_id based on plan duration.
    """
    plan = get_plan(plan_code)
    if not plan:
        raise ValueError("invalid_plan")

    duration_days = int(plan.get("duration_days") or 0)
    if duration_days <= 0:
        raise ValueError("invalid_plan_duration")

    expires = _now_utc() + timedelta(days=duration_days)

    row = {
        "account_id": account_id,
        "plan_code": plan["plan_code"],
        "status": status,
        "expires_at": _iso(expires),
        "updated_at": _iso(_now_utc()),
    }

    # Upsert by account_id (requires unique constraint in DB ideally)
    res = _sb().table("subscriptions").upsert(row, on_conflict="account_id").execute()
    data = getattr(res, "data", None) or []
    return data[0] if data else row
