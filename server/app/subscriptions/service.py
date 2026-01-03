from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(v) -> Optional[datetime]:
    if not v:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    # Supabase often returns ISO strings
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except Exception:
        return None


@dataclass
class SubStatus:
    is_active: bool
    status: str
    plan: Optional[str]
    expires_at: Optional[datetime]


def get_subscription(supabase, wa_phone: str) -> Optional[Dict[str, Any]]:
    res = (
        supabase.table("user_subscriptions")
        .select("*")
        .eq("wa_phone", wa_phone)
        .limit(1)
        .execute()
    )
    data = res.data or []
    return data[0] if data else None


def mark_expired_if_needed(supabase, wa_phone: str) -> SubStatus:
    """
    Lazy-expiry check:
    - If status=active but expires_at < now -> mark status=expired
    - Returns current computed active state
    """
    row = get_subscription(supabase, wa_phone)
    if not row:
        return SubStatus(is_active=False, status="none", plan=None, expires_at=None)

    status = (row.get("status") or "").lower()
    plan = row.get("plan")
    expires_at = _parse_dt(row.get("expires_at"))

    now = _utcnow()

    if status == "active" and expires_at and expires_at <= now:
        # mark expired
        supabase.table("user_subscriptions").update({
            "status": "expired",
            "last_event": "auto_expired",
            "updated_at": now.isoformat(),
        }).eq("wa_phone", wa_phone).execute()
        return SubStatus(is_active=False, status="expired", plan=plan, expires_at=expires_at)

    # active only if status active AND expires_at in future (or expires_at missing but active)
    is_active = (status == "active") and (expires_at is None or expires_at > now)
    return SubStatus(is_active=is_active, status=status, plan=plan, expires_at=expires_at)


def upsert_pending_payment(
    supabase,
    wa_phone: str,
    plan: str,
    reference: str,
) -> None:
    now = _utcnow().isoformat()
    supabase.table("user_subscriptions").upsert({
        "wa_phone": wa_phone,
        "plan": plan,
        "status": "pending",
        "paystack_reference": reference,
        "last_event": "initialize_created",
        "updated_at": now,
    }).execute()


def activate_or_extend_subscription(
    supabase,
    reference: str,
    plan: str,
    plan_days: int,
) -> None:
    """
    Called from webhook on charge.success.
    Renewal behavior:
    - If current subscription is active and expires_at is in future:
        extend from current expires_at
    - Else:
        start from now
    """
    now = _utcnow()

    # find row by reference
    res = (
        supabase.table("user_subscriptions")
        .select("*")
        .eq("paystack_reference", reference)
        .limit(1)
        .execute()
    )
    rows = res.data or []
    current = rows[0] if rows else None

    current_expires = _parse_dt(current.get("expires_at")) if current else None
    current_status = (current.get("status") or "").lower() if current else ""

    start_point = now
    if current_status == "active" and current_expires and current_expires > now:
        start_point = current_expires  # extend from existing expiry

    new_expires = (start_point + timedelta(days=plan_days)).isoformat()

    supabase.table("user_subscriptions").update({
        "status": "active",
        "plan": plan,
        "expires_at": new_expires,
        "last_event": "charge.success",
        "updated_at": now.isoformat(),
    }).eq("paystack_reference", reference).execute()
