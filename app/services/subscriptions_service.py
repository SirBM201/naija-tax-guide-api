# app/services/subscriptions_service.py
from __future__ import annotations

import uuid
from datetime import datetime, timezone
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


def get_subscription_status(account_id: str) -> Dict[str, Any]:
    """
    Returns a normalized subscription status object used by ask_service.
    Expected table: public.user_subscriptions
    """
    req_id = str(uuid.uuid4())
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "missing_account_id", "request_id": req_id}

    try:
        res = (
            supabase.table("user_subscriptions")
            .select("status, plan_code, current_period_end, started_at, updated_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        row = rows[0] if rows else None

        # Default = free user
        if not row:
            return {
                "ok": True,
                "request_id": req_id,
                "is_paid": False,
                "plan_code": "free",
                "status": "none",
                "current_period_end": None,
            }

        status = (row.get("status") or "").lower()
        plan_code = (row.get("plan_code") or "free").lower()
        end_at = row.get("current_period_end")

        # Determine paid
        is_paid = status == "active"
        # If end date exists and already passed, treat as not paid
        try:
            if end_at:
                end_dt = datetime.fromisoformat(str(end_at).replace("Z", "+00:00"))
                if end_dt <= _utcnow():
                    is_paid = False
        except Exception:
            pass

        return {
            "ok": True,
            "request_id": req_id,
            "is_paid": bool(is_paid),
            "plan_code": plan_code,
            "status": status or "unknown",
            "current_period_end": end_at,
        }

    except Exception as e:
        return {
            "ok": False,
            "error": "get_subscription_status_failed",
            "request_id": req_id,
            "root_cause": _rootcause(
                "subscriptions_service.get_subscription_status",
                e,
                req_id=req_id,
                hint="Failed reading user_subscriptions. Ensure table exists and backend uses SUPABASE_SERVICE_ROLE_KEY.",
                extra={"account_id": account_id},
            ),
        }
