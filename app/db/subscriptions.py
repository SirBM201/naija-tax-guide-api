# app/db/subscriptions.py
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from supabase import create_client

from app.core.config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY


_sb = None


def _client():
    global _sb
    if _sb is not None:
        return _sb
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Supabase ENV not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).")
    _sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _sb


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        # Support "Z" suffix
        v = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def get_subscription_row(wa_phone: str) -> Optional[Dict[str, Any]]:
    """
    Returns the latest row for wa_phone from user_subscriptions or None.
    """
    if not wa_phone:
        return None
    sb = _client()
    try:
        r = (
            sb.table("user_subscriptions")
            .select("wa_phone,plan,status,expires_at,updated_at")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        logging.exception("get_subscription_row failed")
        return None


def get_plan_expiry_iso(wa_phone: str) -> Optional[str]:
    """
    Returns ISO expiry string if exists, else None.
    """
    row = get_subscription_row(wa_phone)
    if not row:
        return None
    exp = row.get("expires_at")
    return exp if isinstance(exp, str) and exp.strip() else None


def is_subscription_active(wa_phone: str) -> bool:
    """
    Active if:
      - row exists
      - status == 'active' (case-insensitive) OR status missing but expiry in future
      - expires_at is in the future
    """
    row = get_subscription_row(wa_phone)
    if not row:
        return False

    status = (row.get("status") or "").strip().lower()
    exp = _parse_dt(row.get("expires_at"))

    if exp is None:
        # No expiry => treat as inactive unless explicitly active (you can change this rule later)
        return status == "active"

    now = datetime.now(timezone.utc)
    if exp <= now:
        return False

    # If expiry is valid, treat as active even if status field is imperfect
    if status in ("active", ""):
        return True

    # allow common variants
    return status in ("paid", "subscribed")
