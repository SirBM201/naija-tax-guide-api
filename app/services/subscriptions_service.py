# app/services/subscriptions_service.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase


# -----------------------------
# Helpers
# -----------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str | None) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sb():
    # support both "supabase instance" and "factory"
    return supabase() if callable(supabase) else supabase


def _find_account_id(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Optional[str]:
    """
    If account_id is given -> use it.
    Else try to find account by (provider, provider_user_id) from accounts table.
    """
    if account_id:
        v = account_id.strip()
        return v or None

    if not provider or not provider_user_id:
        return None

    sb = _sb()
    res = (
        sb.table("accounts")
        .select("account_id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    if not rows:
        return None
    return (rows[0].get("account_id") or "").strip() or None


# -----------------------------
# Core API
# -----------------------------
def get_subscription_status(
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Returns a stable frontend-friendly shape.
    """
    resolved = _find_account_id(account_id, provider, provider_user_id)

    out = {
        "account_id": resolved,
        "active": False,
        "expires_at": None,
        "grace_until": None,
        "plan_code": None,
        "reason": "none",
        "state": "none",  # none|active|grace|expired
    }

    if not resolved:
        out["reason"] = "no_account"
        return out

    sb = _sb()
    try:
        res = (
            sb.table("subscriptions")
            .select("account_id, plan_code, status, expires_at, grace_until, next_plan_code, updated_at")
            .eq("account_id", resolved)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            out["reason"] = "no_subscription"
            return out

        row = rows[0] or {}
        out["plan_code"] = row.get("plan_code")
        out["expires_at"] = row.get("expires_at")
        out["grace_until"] = row.get("grace_until")

        now = _now_utc()
        exp = _parse_iso(row.get("expires_at"))
        grace = _parse_iso(row.get("grace_until"))

        if exp and now <= exp:
            out["active"] = True
            out["state"] = "active"
            out["reason"] = "active"
            return out

        # expired but still in grace window
        if grace and now <= grace:
            out["active"] = True
            out["state"] = "grace"
            out["reason"] = "grace"
            return out

        out["active"] = False
        out["state"] = "expired"
        out["reason"] = "expired"
        return out

    except Exception:
        out["reason"] = "status_lookup_failed"
        return out


def activate_subscription_now(
    account_id: str,
    plan_code: str,
    status: str = "active",
    duration_days: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Activates immediately. If duration_days is None, use defaults:
      monthly=30, quarterly=90, yearly=365, trial=7
    """
    plan_code = (plan_code or "").strip().lower() or "manual"
    now = _now_utc()

    default_days = {
        "monthly": 30,
        "quarterly": 90,
        "yearly": 365,
        "trial": 7,
        "manual": 30,
    }
    days = duration_days if isinstance(duration_days, int) and duration_days > 0 else default_days.get(plan_code, 30)
    expires_at = now + timedelta(days=days)

    sb = _sb()
    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": status,
        "expires_at": _iso(expires_at),
        "grace_until": None,
        "next_plan_code": None,
        "updated_at": _iso(now),
    }

    # upsert by account_id
    res = sb.table("subscriptions").upsert(payload, on_conflict="account_id").execute()
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else payload


def manual_activate_subscription(
    account_id: str,
    plan_code: str = "manual",
    expires_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Admin tool: set any plan_code + optional exact expiry timestamp.
    """
    now = _now_utc()
    exp = _parse_iso(expires_at) if expires_at else None
    if exp is None:
        # if not provided, default 30 days
        exp = now + timedelta(days=30)

    sb = _sb()
    payload = {
        "account_id": account_id,
        "plan_code": (plan_code or "manual").strip().lower(),
        "status": "active",
        "expires_at": _iso(exp),
        "grace_until": None,
        "next_plan_code": None,
        "updated_at": _iso(now),
    }
    res = sb.table("subscriptions").upsert(payload, on_conflict="account_id").execute()
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else payload


def start_trial_if_eligible(account_id: str, trial_plan_code: str = "trial") -> Dict[str, Any]:
    """
    Starts a trial only if user has no subscription row yet.
    (You can tighten this later with a 'trial_used' flag if you want.)
    """
    sb = _sb()
    try:
        res = (
            sb.table("subscriptions")
            .select("account_id")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if rows:
            return {"ok": False, "error": "trial_not_eligible", "reason": "already_has_subscription"}

        sub = activate_subscription_now(account_id=account_id, plan_code=trial_plan_code, status="active", duration_days=7)
        return {"ok": True, "subscription": sub}

    except Exception:
        return {"ok": False, "error": "trial_failed"}


def schedule_plan_change_at_expiry(account_id: str, next_plan_code: str) -> Dict[str, Any]:
    """
    Stores next_plan_code on the subscription row. A cron job (or webhook verification)
    can later apply it when expires_at is reached.
    """
    sb = _sb()
    now = _now_utc()

    # Ensure row exists
    res = (
        sb.table("subscriptions")
        .select("account_id, plan_code, status, expires_at, grace_until, next_plan_code")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    if not rows:
        # create a minimal row (inactive) with immediate next_plan_code
        payload = {
            "account_id": account_id,
            "plan_code": None,
            "status": "none",
            "expires_at": None,
            "grace_until": None,
            "next_plan_code": (next_plan_code or "").strip().lower(),
            "updated_at": _iso(now),
        }
        up = sb.table("subscriptions").upsert(payload, on_conflict="account_id").execute()
        data = getattr(up, "data", None) or []
        return data[0] if data else payload

    # update existing
    upd = (
        sb.table("subscriptions")
        .update({"next_plan_code": (next_plan_code or "").strip().lower(), "updated_at": _iso(now)})
        .eq("account_id", account_id)
        .execute()
    )
    data = getattr(upd, "data", None) or []
    return data[0] if data else rows[0]
