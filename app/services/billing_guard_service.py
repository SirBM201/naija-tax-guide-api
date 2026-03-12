from __future__ import annotations

from typing import Any, Dict

from app.services.subscription_guard import get_subscription_snapshot
from app.services.credits_service import get_credit_balance_details, get_daily_usage
from app.repositories.monthly_usage_repo import (
    get_account_monthly_ai_limit,
    get_monthly_ai_usage,
)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def get_billing_state(account_id: str) -> Dict[str, Any]:
    """
    Unified billing state for ask/debug flows.

    IMPORTANT:
    Use user_subscriptions snapshot instead of the older/non-authoritative
    'subscriptions' table reference, so billing/ask logic stays aligned.
    """
    account_id = (account_id or "").strip()

    sub_snapshot = get_subscription_snapshot(account_id)
    access = (sub_snapshot or {}).get("access") or {}
    sub = (sub_snapshot or {}).get("subscription") or {}
    plan = (sub_snapshot or {}).get("plan") or {}

    credit_details = get_credit_balance_details(account_id)
    daily_usage = get_daily_usage(account_id)
    monthly_limit_info = get_account_monthly_ai_limit(account_id)
    monthly_ai_usage = _as_int(get_monthly_ai_usage(account_id), 0)
    monthly_ai_limit = _as_int(monthly_limit_info.get("monthly_ai_limit"), 0)

    return {
        "account_id": account_id,
        "subscription_ok": bool((sub_snapshot or {}).get("ok", False)),
        "subscription_status": str(sub.get("status") or access.get("status") or "unknown"),
        "is_active": bool((sub_snapshot or {}).get("active_now", False)),
        "plan_code": (
            (sub_snapshot or {}).get("plan_code")
            or monthly_limit_info.get("plan_code")
            or "monthly"
        ),
        "expires_at": sub.get("expires_at"),
        "credit_balance": _as_int((credit_details or {}).get("balance"), 0),
        "credit_exists": bool((credit_details or {}).get("exists", False)),
        "daily_usage_count": _as_int((daily_usage or {}).get("count"), 0),
        "daily_usage_day": (daily_usage or {}).get("day"),
        "daily_answers_limit": _as_int((plan or {}).get("daily_answers_limit"), 0),
        "monthly_ai_usage": monthly_ai_usage,
        "monthly_ai_limit": monthly_ai_limit,
        "access": access,
    }
