# app/services/subscription_guard.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _clip(s: Any, n: int = 240) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _safe_dt(v: Any) -> Optional[datetime]:
    try:
        if not v:
            return None
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _normalize_sub_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row.get("id"),
        "account_id": row.get("account_id"),
        "plan_code": row.get("plan_code"),
        "status": (row.get("status") or "").strip().lower(),
        "is_active": bool(row.get("is_active")),
        "started_at": row.get("started_at"),
        "expires_at": row.get("expires_at"),
        "trial_until": row.get("trial_until"),
        "grace_until": row.get("grace_until"),
        "current_period_end": row.get("current_period_end"),
        "provider": row.get("provider"),
        "provider_ref": row.get("provider_ref"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def get_subscription_snapshot(account_id: str) -> Dict[str, Any]:
    account_id = (account_id or "").strip()
    if not account_id:
        return {
            "ok": False,
            "error": "account_id_required",
            "root_cause": "missing_account_id",
            "fix": "Pass canonical account_id to the subscription guard.",
        }

    try:
        res = (
            _sb()
            .table("user_subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
    except Exception as e:
        return {
            "ok": False,
            "error": "subscription_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check user_subscriptions table access and Supabase connectivity.",
            "details": {"account_id": account_id},
        }

    if not rows:
        return {
            "ok": True,
            "account_id": account_id,
            "subscription": None,
            "access": {
                "allowed": False,
                "reason": "no_subscription",
                "status": "none",
                "upgrade_required": True,
            },
        }

    sub = _normalize_sub_row(rows[0] or {})
    now = _now_utc()

    expires_at = _safe_dt(sub.get("expires_at"))
    trial_until = _safe_dt(sub.get("trial_until"))
    grace_until = _safe_dt(sub.get("grace_until"))

    status = (sub.get("status") or "").strip().lower()
    is_active = bool(sub.get("is_active"))

    allowed = False
    reason = "inactive_subscription"

    if is_active and status == "active":
        if expires_at is None or now < expires_at:
            allowed = True
            reason = "active"
        else:
            allowed = False
            reason = "expired"

    elif status == "trial":
        if trial_until and now < trial_until:
            allowed = True
            reason = "trial"
        else:
            allowed = False
            reason = "trial_expired"

    elif status in {"grace", "past_due"}:
        if grace_until and now < grace_until:
            allowed = True
            reason = "grace"
        else:
            allowed = False
            reason = "grace_expired"

    elif status == "expired":
        allowed = False
        reason = "expired"

    elif status == "inactive":
        allowed = False
        reason = "inactive"

    elif status == "cancelled":
        if expires_at and now < expires_at:
            allowed = True
            reason = "active_until_period_end"
        else:
            allowed = False
            reason = "cancelled"

    return {
        "ok": True,
        "account_id": account_id,
        "subscription": sub,
        "access": {
            "allowed": allowed,
            "reason": reason,
            "status": status or ("active" if is_active else "inactive"),
            "upgrade_required": not allowed,
        },
    }


def require_active_subscription(account_id: str) -> Dict[str, Any]:
    snap = get_subscription_snapshot(account_id)
    if not snap.get("ok"):
        return snap

    access = snap.get("access") or {}
    if access.get("allowed"):
        return {
            "ok": True,
            "account_id": account_id,
            "subscription": snap.get("subscription"),
            "access": access,
        }

    sub = snap.get("subscription")
    return {
        "ok": False,
        "error": "subscription_required",
        "root_cause": access.get("reason") or "inactive_subscription",
        "fix": "Upgrade or reactivate billing before using paid AI endpoints.",
        "details": {
            "account_id": account_id,
            "subscription": sub,
            "access": access,
            "recommended_action": "upgrade_plan",
        },
    }
