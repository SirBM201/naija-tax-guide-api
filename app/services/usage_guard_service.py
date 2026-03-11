from __future__ import annotations

from typing import Dict, Any

from app.repositories.monthly_usage_repo import get_account_monthly_ai_limit, get_monthly_ai_usage


def get_ai_usage_state(account_id: str) -> Dict[str, Any]:
    usage = get_monthly_ai_usage(account_id)
    limit_info = get_account_monthly_ai_limit(account_id)
    limit_value = int(limit_info.get("monthly_ai_limit") or 0)

    return {
        "monthly_ai_usage": usage,
        "monthly_ai_limit": limit_value,
        "has_ai_credit": usage < limit_value if limit_value > 0 else False,
        "plan_code": limit_info.get("plan_code") or "monthly",
    }
