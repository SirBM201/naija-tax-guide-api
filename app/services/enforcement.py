# app/services/enforcement.py
from typing import Optional, Tuple
from app.core.config import FREE_DAILY_TOTAL_LIMIT, PAID_DAILY_TOTAL_LIMIT, PRICING_PATH
from app.db.subscriptions import is_subscribed
from app.db.usage import get_today_total
from app.db.ledger import remaining_credits

def enforce_daily_total_limit_or_message(wa_phone: str) -> Optional[str]:
    """
    Returns a user-facing message if blocked, else None.
    """
    subscribed = is_subscribed(wa_phone)
    limit = PAID_DAILY_TOTAL_LIMIT if subscribed else FREE_DAILY_TOTAL_LIMIT

    used_today = get_today_total(wa_phone)
    if used_today >= limit:
        if subscribed:
            return "You have reached your daily usage limit for today. Please try again tomorrow."
        return f"You have reached today's free usage limit. Please subscribe here: {PRICING_PATH}"

    return None

def can_use_ai_for_cost(wa_phone: str, cost: int) -> Tuple[bool, str]:
    """
    Checks monthly AI credits (ai_credit_wallet).
    """
    rem = remaining_credits(wa_phone)
    if rem >= int(cost):
        return True, ""
    return False, f"You have insufficient AI credits ({rem} remaining). Please subscribe/renew here: {PRICING_PATH}"
