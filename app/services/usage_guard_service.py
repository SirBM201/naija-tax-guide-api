from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    raw = str(os.getenv(name, "")).strip()
    try:
        return int(raw) if raw else default
    except Exception:
        return default


def _env_str(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: Any) -> Optional[datetime]:
    if value in (None, "", "null"):
        return None

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    s = str(value).strip()
    if not s:
        return None

    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _coalesce_int(*values: Any, default: int = 0) -> int:
    for v in values:
        if v is None or v == "":
            continue
        try:
            return int(v)
        except Exception:
            try:
                return int(float(v))
            except Exception:
                continue
    return default


def _coalesce_str(*values: Any, default: str = "") -> str:
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if s:
            return s
    return default


def _is_dev_environment() -> bool:
    env = _env_str("APP_ENV") or _env_str("FLASK_ENV") or _env_str("ENV")
    return env.lower() in {"dev", "development", "local", "test", "testing"}


def _safe_dev_bypass_enabled() -> bool:
    """
    Safe dev bypass is ONLY active when:
      1) DEV_BYPASS_AI_CREDITS=1
      2) environment is dev/local/test
    """
    return _truthy(os.getenv("DEV_BYPASS_AI_CREDITS")) and _is_dev_environment()


@dataclass
class UsageState:
    account_id: str
    has_ai_credit: bool
    raw_has_ai_credit: bool
    dev_bypass_active: bool
    credits_left: int
    monthly_ai_usage: int
    monthly_ai_limit: int
    daily_ai_usage: int
    daily_ai_limit: int
    subscription_status: str
    subscription_active: bool
    expires_at: Optional[str]
    plan_code: str
    plan_name: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "has_ai_credit": self.has_ai_credit,
            "raw_has_ai_credit": self.raw_has_ai_credit,
            "dev_bypass_active": self.dev_bypass_active,
            "credits_left": self.credits_left,
            "monthly_ai_usage": self.monthly_ai_usage,
            "monthly_ai_limit": self.monthly_ai_limit,
            "daily_ai_usage": self.daily_ai_usage,
            "daily_ai_limit": self.daily_ai_limit,
            "subscription_status": self.subscription_status,
            "subscription_active": self.subscription_active,
            "expires_at": self.expires_at,
            "plan_code": self.plan_code,
            "plan_name": self.plan_name,
        }


def _safe_select_one(table: str, account_id: str) -> Dict[str, Any]:
    try:
        client = _sb()
        res = (
            client.table(table)
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        data = getattr(res, "data", None) or []
        if isinstance(data, list) and data:
            return data[0] or {}
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}


def _load_usage_row(account_id: str) -> Dict[str, Any]:
    for table in ("ai_usage", "usage_state", "account_usage"):
        row = _safe_select_one(table, account_id)
        if row:
            return row
    return {}


def _load_subscription_row(account_id: str) -> Dict[str, Any]:
    for table in ("user_subscriptions", "subscriptions", "billing_accounts"):
        row = _safe_select_one(table, account_id)
        if row:
            return row
    return {}


def _load_account_row(account_id: str) -> Dict[str, Any]:
    return _safe_select_one("accounts", account_id) or {}


def _subscription_active(sub_row: Dict[str, Any], account_row: Dict[str, Any]):
    status = _coalesce_str(
        sub_row.get("status"),
        sub_row.get("subscription_status"),
        account_row.get("subscription_status"),
        default="inactive",
    ).lower()

    expires_at_raw = (
        sub_row.get("expires_at")
        or sub_row.get("current_period_end")
        or sub_row.get("plan_expires_at")
        or account_row.get("expires_at")
        or account_row.get("plan_expires_at")
    )

    expires_dt = _parse_dt(expires_at_raw)

    plan_code = _coalesce_str(
        sub_row.get("plan_code"),
        sub_row.get("plan"),
        account_row.get("plan_code"),
        account_row.get("plan"),
        default="free",
    )

    plan_name = _coalesce_str(
        sub_row.get("plan_name"),
        account_row.get("plan_name"),
        default=plan_code or "free",
    )

    status_active = status in {"active", "trialing", "paid", "grace"}
    time_active = expires_dt is None or expires_dt > _now()

    active = status_active and time_active

    return (
        active,
        status,
        expires_dt.isoformat() if expires_dt else None,
        plan_code,
        plan_name,
    )


def _resolve_limits(usage_row: Dict[str, Any], sub_row: Dict[str, Any], account_row: Dict[str, Any]):
    monthly_limit = _coalesce_int(
        usage_row.get("monthly_ai_limit"),
        sub_row.get("monthly_ai_limit"),
        account_row.get("monthly_ai_limit"),
        default=_env_int("DEFAULT_MONTHLY_AI_LIMIT", 20),
    )

    daily_limit = _coalesce_int(
        usage_row.get("daily_ai_limit"),
        sub_row.get("daily_ai_limit"),
        account_row.get("daily_ai_limit"),
        default=_env_int("DEFAULT_DAILY_AI_LIMIT", 20),
    )

    return monthly_limit, daily_limit


def _resolve_usage(usage_row: Dict[str, Any], account_row: Dict[str, Any]):
    credits_left = _coalesce_int(
        usage_row.get("credits_left"),
        usage_row.get("remaining_credits"),
        account_row.get("credits_left"),
        account_row.get("remaining_credits"),
        default=0,
    )

    monthly_ai_usage = _coalesce_int(
        usage_row.get("monthly_ai_usage"),
        account_row.get("monthly_ai_usage"),
        default=0,
    )

    daily_ai_usage = _coalesce_int(
        usage_row.get("daily_ai_usage"),
        account_row.get("daily_ai_usage"),
        default=0,
    )

    return credits_left, monthly_ai_usage, daily_ai_usage


def get_ai_usage_state(account_id: str) -> Dict[str, Any]:
    usage_row = _load_usage_row(account_id)
    sub_row = _load_subscription_row(account_id)
    account_row = _load_account_row(account_id)

    credits_left, monthly_ai_usage, daily_ai_usage = _resolve_usage(usage_row, account_row)
    monthly_ai_limit, daily_ai_limit = _resolve_limits(usage_row, sub_row, account_row)

    (
        subscription_active,
        subscription_status,
        expires_at,
        plan_code,
        plan_name,
    ) = _subscription_active(sub_row, account_row)

    within_monthly_limit = monthly_ai_usage < monthly_ai_limit if monthly_ai_limit > 0 else True
    within_daily_limit = daily_ai_usage < daily_ai_limit if daily_ai_limit > 0 else True

    raw_has_ai_credit = bool(subscription_active and within_monthly_limit and within_daily_limit)

    dev_bypass_active = _safe_dev_bypass_enabled()

    has_ai_credit = True if dev_bypass_active else raw_has_ai_credit

    state = UsageState(
        account_id=account_id,
        has_ai_credit=has_ai_credit,
        raw_has_ai_credit=raw_has_ai_credit,
        dev_bypass_active=dev_bypass_active,
        credits_left=credits_left,
        monthly_ai_usage=monthly_ai_usage,
        monthly_ai_limit=monthly_ai_limit,
        daily_ai_usage=daily_ai_usage,
        daily_ai_limit=daily_ai_limit,
        subscription_status=subscription_status,
        subscription_active=subscription_active,
        expires_at=expires_at,
        plan_code=plan_code,
        plan_name=plan_name,
    )

    return state.to_dict()
