# app/services/enforcement.py
from app.core.config import FREE_DAILY_TOTAL_LIMIT, PAID_DAILY_TOTAL_LIMIT, MONTHLY_AI_CREDITS
from app.core.utils import parse_iso_dt, now_utc
from app.db.subscriptions import get_subscription_row
from app.db.ledger import ledger_get_balance, ledger_ensure_monthly_topup
from app.db.usage import get_daily_total_count


def enforce_daily_total_limit_or_message(wa_phone: str) -> str | None:
    """
    Returns a message if blocked, else None.
    """
    sub = get_subscription_row(wa_phone)
    is_paid = False
    if sub and (sub.get("status") == "active"):
        exp = parse_iso_dt(sub.get("expires_at"))
        if exp and exp > now_utc():
            is_paid = True

    limit = PAID_DAILY_TOTAL_LIMIT if is_paid else FREE_DAILY_TOTAL_LIMIT
    used = get_daily_total_count(wa_phone)
    if used >= limit:
        return f"You have reached your daily limit ({limit} questions). Please try again tomorrow."
    return None


def can_use_ai_for_cost(wa_phone: str, cost: int) -> tuple[bool, str | None]:
    """
    AI usage is controlled by a monthly 'ledger balance'.
    - Paid users: we auto-topup monthly credits.
    - Free users: no monthly credits by default (AI blocked unless you manually credit them).
    """
    # If paid and active -> ensure monthly topup exists
    sub = get_subscription_row(wa_phone)
    if sub and (sub.get("status") == "active"):
        ledger_ensure_monthly_topup(wa_phone, MONTHLY_AI_CREDITS)

    bal = ledger_get_balance(wa_phone)
    if bal >= cost:
        return True, None
    return False, "You have no AI credits remaining. Please subscribe or top up."
