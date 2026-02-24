# app/services/subscriptions_service.py
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _rootcause(where: str, e: Exception, *, req_id: str, hint: str = "", extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "where": where,
        "type": type(e).__name__,
        "message": str(e),
        "request_id": req_id,
    }
    if hint:
        out["hint"] = hint
    if extra:
        out["extra"] = extra
    return out


def activate_subscription_now(*, account_id: str, plan_code: str, days: Optional[int] = None) -> Dict[str, Any]:
    """
    Upsert into public.user_subscriptions keyed by account_id.
    """
    req_id = str(uuid.uuid4())

    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip().lower()
    if not account_id:
        return {"ok": False, "error": "missing_account_id", "request_id": req_id}
    if plan_code not in ("monthly", "quarterly", "yearly"):
        return {"ok": False, "error": "invalid_plan_code", "request_id": req_id, "extra": {"plan_code": plan_code}}

    if days is None:
        days = {"monthly": 30, "quarterly": 90, "yearly": 365}[plan_code]

    now = _utcnow()
    end_at = now + timedelta(days=int(days))

    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": "active",
        "started_at": now.isoformat(),
        "current_period_end": end_at.isoformat(),
        "updated_at": now.isoformat(),
    }

    try:
        # ✅ supabase is a CLIENT, so .table() works
        res = (
            supabase
            .table("user_subscriptions")
            .upsert(payload, on_conflict="account_id")
            .execute()
        )

        return {
            "ok": True,
            "message": "subscription_activated",
            "request_id": req_id,
            "data": getattr(res, "data", None),
            "period_end": payload["current_period_end"],
        }

    except Exception as e:
        return {
            "ok": False,
            "error": "activate_subscription_failed",
            "message": "could not activate subscription",
            "request_id": req_id,
            "root_cause": _rootcause(
                "subscriptions_service.activate_subscription_now",
                e,
                req_id=req_id,
                hint="DB upsert failed (user_subscriptions). Ensure table exists, account_id type is uuid, and SERVICE ROLE key is used in backend.",
                extra={"account_id": account_id, "plan_code": plan_code, "days": days},
            ),
        }


def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    req_id = str(uuid.uuid4())
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "missing_account_id", "request_id": req_id}

    try:
        res = (
            supabase
            .table("user_subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return {"ok": True, "request_id": req_id, "row": (rows[0] if rows else None)}

    except Exception as e:
        return {
            "ok": False,
            "error": "debug_read_subscription_failed",
            "message": "could not read subscription for debug",
            "request_id": req_id,
            "root_cause": _rootcause(
                "subscriptions_service.debug_read_subscription",
                e,
                req_id=req_id,
                hint="DB read failed. Check table name, RLS, and backend key.",
                extra={"account_id": account_id},
            ),
        }


def handle_payment_success(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Called by Paystack webhook route.
    Minimal: store paystack event (optional) + activate subscription immediately.
    """
    req_id = str(uuid.uuid4())
    try:
        account_id = (payload.get("account_id") or "").strip()
        plan_code = (payload.get("plan_code") or "").strip().lower()

        if not account_id or not plan_code:
            return {"ok": False, "error": "missing_account_or_plan", "request_id": req_id, "extra": payload}

        # Optional: store event (if table exists)
        try:
            supabase.table("paystack_events").insert({
                "event_id": payload.get("event_id"),
                "event_type": "charge.success",
                "reference": payload.get("reference"),
                "raw": payload.get("raw"),
                "created_at": _utcnow().isoformat(),
            }).execute()
        except Exception:
            # don't fail payment activation because event logging failed
            pass

        # Activate subscription
        out = activate_subscription_now(account_id=account_id, plan_code=plan_code, days=None)
        if not out.get("ok"):
            out["request_id"] = req_id
        return out

    except Exception as e:
        return {
            "ok": False,
            "error": "handle_payment_success_failed",
            "request_id": req_id,
            "root_cause": _rootcause(
                "subscriptions_service.handle_payment_success",
                e,
                req_id=req_id,
                hint="Unexpected error in payment handler.",
                extra=payload,
            ),
        }
