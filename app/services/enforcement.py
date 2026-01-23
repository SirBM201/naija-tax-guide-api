# app/services/enforcement.py
from typing import Optional, Tuple
from app.core.config import FREE_DAILY_TOTAL_LIMIT, PAID_DAILY_TOTAL_LIMIT

# Minimal enforcement for now:
# - If you want strict enforcement based on your DB counters, we can connect it next.
def enforce_daily_total_limit_or_message(wa_phone: str) -> Optional[str]:
    return None

def can_use_ai_for_cost(wa_phone: str, credits_needed: int) -> Tuple[bool, Optional[str]]:
    # For now always allow. Next step: read current credits from ai_credits table and enforce.
    return True, None
