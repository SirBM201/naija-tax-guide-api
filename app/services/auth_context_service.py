# app/services/auth_context_service.py
from __future__ import annotations

from typing import Any, Dict

from app.services.subscription_status_service import get_subscription_status
from app.services.credits_service import get_credit_balance


def build_auth_context(account_id: str) -> Dict[str, Any]:
    sub = get_subscription_status(account_id)
    credits = get_credit_balance(account_id)
    # credits may fail if table missing; keep response stable
    return {
        "subscription": sub,
        "credits": credits if credits.get("ok") else {"ok": False, "balance": 0, "error": credits.get("error")},
    }
