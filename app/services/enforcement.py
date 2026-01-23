# app/services/enforcement.py
from __future__ import annotations

from typing import Optional, Tuple
import logging
from datetime import datetime, timezone

from app.core.config import FREE_DAILY_TOTAL_LIMIT, PAID_DAILY_TOTAL_LIMIT
from app.core.utils import now_utc
from app.db.subscriptions import is_subscription_active
from app.db.usage import daily_total_get


def enforce_daily_total_limit_or_message(wa_phone: str) -> Optional[str]:
    """
    Returns a human-readable message if the user has exceeded daily total limit,
    otherwise None.
    """
    try:
        used = daily_total_get(wa_phone)
    except Exception as e:
        logging.warning("daily_total_get failed (non-fatal): %s", e)
        used = 0

    paid = False
    try:
        paid = is_subscription_active(wa_phone)
    except Exception as e:
        logging.warning("is_subscription_active failed (non-fatal): %s", e)
        paid = False

    limit = PAID_DAILY_TOTAL_LIMIT if paid else FREE_DAILY_TOTAL_LIMIT

    if used >= limit:
        if paid:
            return (
                f"You have reached your daily usage limit ({limit} answers today). "
                "Please try again tomorrow."
            )
        return (
            f"You have reached your free daily limit ({limit} answers today). "
            "Please subscribe to continue."
        )

    return None


def can_use_ai_for_cost(wa_phone: str, credits_needed: int) -> Tuple[bool, str]:
    """
    Returns (allowed, reason).
    We do NOT enforce monthly credits table yet; we enforce:
      - daily total limit
      - subscription required for AI beyond free usage
    """
    msg = enforce_daily_total_limit_or_message(wa_phone)
    if msg:
        return False, msg

    # If user is subscribed, allow AI (subject to daily total above)
    try:
        if is_subscription_active(wa_phone):
            return True, ""
    except Exception:
        pass

    # Not subscribed: block AI usage (library/cache still work)
    return False, "AI answers are available for subscribed users only."
