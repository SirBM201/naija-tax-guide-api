# app/services/subscriptions_service.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from ..core.supabase_client import supabase


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
_PLAN_DAYS: Dict[str, int] = {
    "monthly": 30,
    "quarterly": 90,
    "yearly": 365,
}


# -----------------------------------------------------------------------------
# Small utilities
# -----------------------------------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _norm_plan(plan_code: Optional[str]) -> str:
    return (plan_code or "").strip().lower()


def _duration_days(plan_code: str) -> int:
    return _PLAN_DAYS.get(plan_code, 30)


def _rootcause(where: str, e: Exception, *, hint: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Root-cause exposer (safe):
    - No stack traces
    - No env var dumping
    - Just enough to diagnose quickly
    """
    out: Dict[str, Any] = {
        "where": where,
        "type": type(e).__name__,
        "message": str(e),
    }
    if hint:
        out["hint"] = hint
    if extra:
        out["extra"] = extra
    return out


def _ok(data: Dict[str, Any]) -> Dict[str, Any]:
    return {"ok": True, **data}


def _fail(error: str, *, where: str, e: Optional[Exception] = None, hint: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"ok": False, "error": error}
    if e is not None:
        payload["root_cause"] = _rootcause(where, e, hint=hint, extra=extra)
    else:
        payload["root_cause"] = {"where": where, "message": hint or "unknown"}
        if extra:
            payload["root_cause"]["extra"] = extra
    return payload


# -----------------------------------------------------------------------------
# DB helpers (Supabase in this project is a FACTORY function)
# -----------------------------------------------------------------------------
def _db():
    # IMPORTANT: in your codebase, supabase is a function.
    return supabase()


def _upsert_user_subscription(payload: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Upsert into user_subscriptions using UNIQUE(account_id).
    Returns: (ok, row, error_info)
    """
    try:
        db = _db()
        res = (
            db.table("user_subscriptions")
            .upsert(payload, on_conflict="account_id")
            .select("account_id, plan_code, status, expires_at, grace_until, trial_until, created_at, updated_at")
            .execute()
        )
        rows = getattr(res, "data", None) or []
        row = rows[0] if rows else None
        return True, row, None
    except Exception as e:
        return False, None, _rootcause(
            "user_subscriptions.upsert",
            e,
            hint="Verify table exists, RLS policy allows service role, and Supabase credentials are correct.",
        )


def _get_user_subscription(account_id: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        db = _db()
        res = (
            db.table("user_subscriptions")
            .select("account_id, plan_code, status, expires_at, grace_until, trial_until, created_at, updated_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        row = rows[0] if rows else None
        return True, row, None
    except Exception as e:
        return False, None, _rootcause(
            "user_subscriptions.select",
            e,
            hint="If this fails, check Supabase URL/KEY env vars and RLS policies for user_subscriptions.",
        )


# -----------------------------------------------------------------------------
# Public functions used by routes
# -----------------------------------------------------------------------------
def activate_subscription_now(
    *,
    account_id: str,
    plan_code: str,
    days: Optional[int] = None,
    status: str = "active",
) -> Dict[str, Any]:
    """
    Admin/manual activation (or internal activation after payment).
    Writes to: user_subscriptions (unique on account_id)
    """
    where = "activate_subscription_now"

    account_id = (account_id or "").strip()
    plan_code = _norm_plan(plan_code)

    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")
    if not plan_code:
        return _fail("missing_plan_code", where=where, hint="plan_code is required")

    now = _now_utc()
    dur = int(days) if days is not None else _duration_days(plan_code)
    expires_at = now + timedelta(days=dur)

    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": (status or "active").strip().lower(),
        "expires_at": _iso(expires_at),
        "grace_until": None,
        "trial_until": None,
        "updated_at": _iso(now),
    }

    ok, row, err = _upsert_user_subscription(payload)
    if not ok:
        return {
            "ok": False,
            "error": "db_upsert_failed",
            "root_cause": err,
            "where": where,
            "table": "user_subscriptions",
            "attempted_payload_keys": sorted(list(payload.keys())),
        }

    return _ok({"account_id": account_id, "subscription": row, "table": "user_subscriptions"})


def cancel_subscription(
    *,
    account_id: str,
    status: str = "canceled",
) -> Dict[str, Any]:
    """
    Cancel but keep row for audit.
    """
    where = "cancel_subscription"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    now = _now_utc()
    payload = {
        "account_id": account_id,
        "status": (status or "canceled").strip().lower(),
        "updated_at": _iso(now),
    }

    ok, row, err = _upsert_user_subscription(payload)
    if not ok:
        return {"ok": False, "error": "db_upsert_failed", "root_cause": err, "where": where}

    return _ok({"account_id": account_id, "subscription": row})


def set_trial(
    *,
    account_id: str,
    plan_code: str = "trial",
    trial_days: int = 7,
) -> Dict[str, Any]:
    where = "set_trial"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    now = _now_utc()
    trial_until = now + timedelta(days=int(trial_days))

    payload = {
        "account_id": account_id,
        "plan_code": _norm_plan(plan_code) or "trial",
        "status": "active",
        "trial_until": _iso(trial_until),
        "updated_at": _iso(now),
    }

    ok, row, err = _upsert_user_subscription(payload)
    if not ok:
        return {"ok": False, "error": "db_upsert_failed", "root_cause": err, "where": where}

    return _ok({"account_id": account_id, "subscription": row})


def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    """
    Helper used by debug routes.
    """
    where = "debug_read_subscription"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    ok, row, err = _get_user_subscription(account_id)
    if not ok:
        return {"ok": False, "error": "db_read_failed", "root_cause": err, "where": where}

    return _ok({"account_id": account_id, "subscription": row, "table": "user_subscriptions"})


# -----------------------------------------------------------------------------
# COMPATIBILITY SHIMS (prevent REQUIRED blueprint boot crashes)
# -----------------------------------------------------------------------------
def get_subscription_status(account_id: str) -> Dict[str, Any]:
    """
    app.routes.ask imports get_subscription_status from this module.
    If the 'real' implementation lives elsewhere, delegate safely.
    NEVER crash boot.
    """
    where = "get_subscription_status(shim)"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    # Preferred: new service
    try:
        from .subscription_status_service import get_subscription_status as _gss  # type: ignore
        return _gss(account_id)
    except Exception:
        # Fallback: compute minimal status from user_subscriptions
        ok, row, err = _get_user_subscription(account_id)
        if not ok:
            return {"ok": False, "error": "db_read_failed", "root_cause": err, "where": where}

        if not row:
            return _ok(
                {
                    "account_id": account_id,
                    "status": "free",
                    "plan_code": None,
                    "active": False,
                    "source": "fallback:user_subscriptions(empty)",
                }
            )

        status = (row.get("status") or "").strip().lower() or "unknown"
        expires_at = row.get("expires_at")
        active = status == "active"
        return _ok(
            {
                "account_id": account_id,
                "status": status,
                "plan_code": row.get("plan_code"),
                "expires_at": expires_at,
                "active": active,
                "source": "fallback:user_subscriptions",
            }
        )


def handle_payment_success(
    *,
    account_id: str,
    plan_code: Optional[str] = None,
    days: Optional[int] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    app.routes.webhooks imports handle_payment_success from this module.
    Safe default behavior: activate subscription now.

    Later, if you implement a dedicated payments pipeline, delegate here.
    """
    where = "handle_payment_success(shim)"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    try:
        # If you later create a dedicated handler:
        # from .payments_service import handle_payment_success as _h
        # return _h(account_id=account_id, plan_code=plan_code, days=days, meta=meta)

        return activate_subscription_now(
            account_id=account_id,
            plan_code=(plan_code or "monthly"),
            days=days,
            status="active",
        )
    except Exception as e:
        return _fail(
            "handle_payment_success_failed",
            where=where,
            e=e,
            hint="Activation failed inside webhook success handler. Check DB/RLS and payload values.",
            extra={"plan_code": plan_code, "days": days, "meta_keys": sorted(list((meta or {}).keys()))},
        )


def handle_payment_failed(
    *,
    account_id: str,
    reason: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Optional shim in case webhooks route calls it.
    """
    where = "handle_payment_failed(shim)"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    try:
        return cancel_subscription(account_id=account_id, status="payment_failed")
    except Exception as e:
        return _fail(
            "handle_payment_failed_failed",
            where=where,
            e=e,
            hint="Cancel failed inside webhook failure handler. Check DB/RLS and account_id.",
            extra={"reason": reason, "meta_keys": sorted(list((meta or {}).keys()))},
        )
