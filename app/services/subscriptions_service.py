# app/services/subscriptions_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase
from app.services.subscription_status_service import get_subscription_status as _get_subscription_status

SUBSCRIPTIONS_TABLE = (os.getenv("SUBSCRIPTIONS_TABLE", "") or "user_subscriptions").strip()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(dt: Any) -> Optional[datetime]:
    if not dt:
        return None
    if isinstance(dt, datetime):
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if isinstance(dt, str):
        s = dt.strip()
        if not s:
            return None
        # handle "Z"
        s = s.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s)
        except Exception:
            return None
    return None


def _compute_expiry(plan_code: str) -> datetime:
    """
    Basic plan expiry rules (UTC). Adjust anytime.
    """
    p = (plan_code or "").strip().lower()
    now = _now()

    if p in ("monthly", "month"):
        return now + timedelta(days=30)
    if p in ("quarterly", "quarter"):
        return now + timedelta(days=90)
    if p in ("yearly", "annual", "year"):
        return now + timedelta(days=365)
    if p in ("trial",):
        return now + timedelta(days=7)

    # manual fallback: short expiry so it's never NULL unless you explicitly pass expires_at
    return now + timedelta(days=30)


def activate_subscription_now(
    *,
    account_id: str,
    plan_code: str = "manual",
    status: str = "active",
    expires_at_iso: Any = None,
    grace_until_iso: Any = None,
    trial_until_iso: Any = None,
) -> Dict[str, Any]:
    """
    Upsert a subscription row keyed by account_id.
    Designed for:
    - admin testing (/subscription/activate)
    - webhook activation

    Returns:
      { ok: bool, ... , root_cause?: str }
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "missing_account_id"}

    plan_code = (plan_code or "manual").strip()
    status = (status or "active").strip()

    expires_at = _parse_iso(expires_at_iso)
    grace_until = _parse_iso(grace_until_iso)
    trial_until = _parse_iso(trial_until_iso)

    # If active and expires_at not provided, compute one (prevents NOT NULL/NULL issues)
    if status.lower() == "active" and expires_at is None:
        expires_at = _compute_expiry(plan_code)

    payload: Dict[str, Any] = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": status,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "grace_until": grace_until.isoformat() if grace_until else None,
        "trial_until": trial_until.isoformat() if trial_until else None,
        "updated_at": _now().isoformat(),
    }

    try:
        res = (
            supabase.table(SUBSCRIPTIONS_TABLE)
            .upsert(payload, on_conflict="account_id")
            .execute()
        )
        data = getattr(res, "data", None)
        return {
            "ok": True,
            "table": SUBSCRIPTIONS_TABLE,
            "account_id": account_id,
            "upserted": True,
            "row": (data[0] if isinstance(data, list) and data else data),
        }
    except Exception as e:
        # ✅ Root-cause exposer (safe, but very useful during dev)
        return {
            "ok": False,
            "error": "db_upsert_failed",
            "table": SUBSCRIPTIONS_TABLE,
            "account_id": account_id,
            "payload": payload,
            "root_cause": repr(e),
        }


def handle_payment_success(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Minimal handler: activates subscription immediately.
    event must include account_id + plan_code.
    """
    try:
        account_id = (event.get("account_id") or "").strip()
        plan_code = (event.get("plan_code") or "").strip() or "monthly"
        upgrade_mode = (event.get("upgrade_mode") or "now").strip().lower()

        # for now: treat both now/at_expiry as "activate now"
        out = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active")
        out["provider"] = event.get("provider")
        out["reference"] = event.get("reference")
        out["upgrade_mode"] = upgrade_mode
        return out
    except Exception as e:
        return {"ok": False, "error": "handle_payment_success_failed", "root_cause": repr(e), "event": event}


# Backward-compat export (prevents old imports from crashing)
def get_subscription_status(account_id: str) -> Dict[str, Any]:
    return _get_subscription_status(account_id)
