# app/services/subscriptions_service.py
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from app.core.supabase_client import get_supabase


# -----------------------------
# Helpers
# -----------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _rc(where: str, e: Exception, *, req_id: str, hint: str = "", extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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


def _plan_days(plan_code: str) -> int:
    pc = (plan_code or "").strip().lower()
    if pc in ("monthly", "month"):
        return 30
    if pc in ("quarterly", "quarter"):
        return 90
    if pc in ("yearly", "annual", "year"):
        return 365
    # fallback: treat unknown as monthly
    return 30


# -----------------------------
# Public API: status
# -----------------------------
def get_subscription_status(account_id: str) -> Dict[str, Any]:
    """
    Used by ask_service.py (to enforce free vs paid limits).
    Returns:
      { ok: true, is_paid: bool, plan_code, status, current_period_end, source }
    """
    req_id = str(uuid.uuid4())
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "missing_account_id", "request_id": req_id}

    try:
        supabase = get_supabase()

        res = (
            supabase.table("user_subscriptions")
            .select("account_id, plan_code, status, current_period_end, updated_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        row = rows[0] if rows else None

        if not row:
            return {
                "ok": True,
                "is_paid": False,
                "status": "none",
                "plan_code": None,
                "current_period_end": None,
                "source": "no_row",
                "request_id": req_id,
            }

        cpe = row.get("current_period_end")
        status = (row.get("status") or "").lower()
        plan_code = row.get("plan_code")

        # consider paid if active AND not expired
        is_active = status in ("active", "trialing")
        not_expired = True
        if cpe:
            try:
                # Supabase returns ISO strings
                dt = datetime.fromisoformat(str(cpe).replace("Z", "+00:00"))
                not_expired = dt >= _now_utc()
            except Exception:
                not_expired = True

        return {
            "ok": True,
            "is_paid": bool(is_active and not_expired),
            "status": status,
            "plan_code": plan_code,
            "current_period_end": cpe,
            "source": "user_subscriptions",
            "request_id": req_id,
        }

    except Exception as e:
        return {
            "ok": False,
            "error": "subscription_status_failed",
            "request_id": req_id,
            "root_cause": _rc(
                "subscriptions_service.get_subscription_status",
                e,
                req_id=req_id,
                hint="Supabase read failed. Ensure SUPABASE_URL and SERVICE ROLE KEY are set on Koyeb, "
                     "and that user_subscriptions table exists.",
                extra={"account_id": account_id},
            ),
        }


# -----------------------------
# Public API: admin activate now
# -----------------------------
def activate_subscription_now(*, account_id: str, plan_code: str, days: Optional[int] = None) -> Dict[str, Any]:
    req_id = str(uuid.uuid4())
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "monthly").strip().lower()
    if not account_id:
        return {"ok": False, "error": "missing_account_id", "request_id": req_id}

    if days is None:
        days = _plan_days(plan_code)

    try:
        supabase = get_supabase()

        start = _now_utc()
        end = start + timedelta(days=int(days))

        payload = {
            "account_id": account_id,
            "plan_code": plan_code,
            "status": "active",
            "current_period_start": start.isoformat(),
            "current_period_end": end.isoformat(),
            "updated_at": start.isoformat(),
        }

        # upsert by account_id (requires unique constraint on user_subscriptions.account_id)
        res = (
            supabase.table("user_subscriptions")
            .upsert(payload, on_conflict="account_id")
            .execute()
        )

        return {
            "ok": True,
            "request_id": req_id,
            "account_id": account_id,
            "plan_code": plan_code,
            "status": "active",
            "current_period_start": payload["current_period_start"],
            "current_period_end": payload["current_period_end"],
            "db": {"data": getattr(res, "data", None)},
        }

    except Exception as e:
        return {
            "ok": False,
            "error": "activate_subscription_failed",
            "message": "could not activate subscription",
            "request_id": req_id,
            "root_cause": _rc(
                "subscriptions_service.activate_subscription_now",
                e,
                req_id=req_id,
                hint="DB upsert failed (user_subscriptions). Ensure table exists, account_id column type matches, "
                     "and SUPABASE_SERVICE_ROLE_KEY is used on backend.",
                extra={"account_id": account_id, "plan_code": plan_code, "days": days},
            ),
        }


def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    req_id = str(uuid.uuid4())
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "missing_account_id", "request_id": req_id}

    try:
        supabase = get_supabase()
        res = (
            supabase.table("user_subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .order("updated_at", desc=True)
            .limit(5)
            .execute()
        )
        return {"ok": True, "request_id": req_id, "rows": getattr(res, "data", [])}

    except Exception as e:
        return {
            "ok": False,
            "error": "debug_read_subscription_failed",
            "message": "could not read subscription for debug",
            "request_id": req_id,
            "root_cause": _rc(
                "subscriptions_service.debug_read_subscription",
                e,
                req_id=req_id,
                hint="DB read failed. Check Supabase permissions and that user_subscriptions exists.",
                extra={"account_id": account_id},
            ),
        }


# -----------------------------
# Public API: webhook handler
# -----------------------------
def handle_payment_success(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Called by /webhooks/paystack when Paystack sends charge.success.
    This function should:
      1) dedupe event_id (optional but recommended)
      2) record event in paystack_events
      3) activate/extend subscription
    """
    req_id = str(uuid.uuid4())

    try:
        supabase = get_supabase()

        event_id = (evt.get("event_id") or "").strip()
        reference = (evt.get("reference") or "").strip()
        account_id = (evt.get("account_id") or "").strip()
        plan_code = (evt.get("plan_code") or "").strip().lower()
        upgrade_mode = (evt.get("upgrade_mode") or "now").strip().lower()

        if not account_id or not plan_code:
            return {
                "ok": False,
                "error": "missing_account_or_plan",
                "request_id": req_id,
                "root_cause": {"where": "handle_payment_success.input", "message": "account_id and plan_code are required", "request_id": req_id},
            }

        # 1) store paystack event (best-effort)
        try:
            if event_id or reference:
                supabase.table("paystack_events").insert(
                    {
                        "event_id": event_id or None,
                        "event_type": "charge.success",
                        "reference": reference or None,
                        "account_id": account_id,
                        "plan_code": plan_code,
                        "raw": evt.get("raw"),
                        "created_at": _now_utc().isoformat(),
                    }
                ).execute()
        except Exception:
            # do not block subscription if logging fails
            pass

        # 2) apply subscription
        # For now, treat both "now" and "at_expiry" as activate-now (simple MVP).
        # You can later implement "at_expiry" queueing.
        out = activate_subscription_now(account_id=account_id, plan_code=plan_code, days=None)
        if not out.get("ok"):
            out["request_id"] = req_id
            return out

        out["request_id"] = req_id
        out["upgrade_mode"] = upgrade_mode
        out["reference"] = reference
        return out

    except Exception as e:
        return {
            "ok": False,
            "error": "handle_payment_success_failed",
            "request_id": req_id,
            "root_cause": _rc(
                "subscriptions_service.handle_payment_success",
                e,
                req_id=req_id,
                hint="Unexpected failure in webhook handler.",
                extra={"evt_keys": list((evt or {}).keys())},
            ),
        }
