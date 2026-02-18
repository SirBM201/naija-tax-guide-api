# app/services/subscription_status_service.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..core.supabase_client import supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def get_subscription_status(account_id: str) -> Dict[str, Any]:
    """
    Source of truth: public.user_subscriptions

    Returns:
      {
        active: bool,
        state: "active"|"grace"|"expired"|"none",
        plan_code: str|null,
        expires_at: str|null,
        grace_until: str|null,
        reason: str
      }
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return {
            "active": False,
            "state": "none",
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
            "reason": "no_account_id",
        }

    try:
        db = supabase()
        res = (
            db.table("user_subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        row = rows[0] if rows else None
    except Exception:
        row = None

    if not row:
        return {
            "active": False,
            "state": "none",
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
            "reason": "no_subscription",
        }

    plan_code = row.get("plan_code")
    expires_at = row.get("expires_at")
    grace_until = row.get("grace_until")

    now = _now_utc()
    exp_dt = _parse_iso(expires_at)
    grace_dt = _parse_iso(grace_until)

    if exp_dt and exp_dt > now:
        return {
            "active": True,
            "state": "active",
            "plan_code": plan_code,
            "expires_at": expires_at,
            "grace_until": grace_until,
            "reason": "within_expiry",
        }

    if grace_dt and grace_dt > now:
        return {
            "active": True,
            "state": "grace",
            "plan_code": plan_code,
            "expires_at": expires_at,
            "grace_until": grace_until,
            "reason": "within_grace",
        }

    return {
        "active": False,
        "state": "expired",
        "plan_code": plan_code,
        "expires_at": expires_at,
        "grace_until": grace_until,
        "reason": "expired",
    }
