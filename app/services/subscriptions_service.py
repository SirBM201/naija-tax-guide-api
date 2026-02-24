# app/services/subscriptions_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase


# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
DEFAULT_PLAN_CODE = (os.getenv("DEFAULT_FREE_PLAN_CODE") or "free").strip() or "free"
DEFAULT_DAYS = int((os.getenv("DEFAULT_SUBSCRIPTION_DAYS") or "30").strip() or "30")

RPC_READ = (os.getenv("SUBSCRIPTION_RPC_READ") or "bms_read_subscription").strip() or "bms_read_subscription"
RPC_ACTIVATE = (os.getenv("SUBSCRIPTION_RPC_ACTIVATE") or "bms_activate_subscription").strip() or "bms_activate_subscription"


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _as_int(v: Any, default: int) -> int:
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return default
        return int(v)
    except Exception:
        return default


def _ok(**k: Any) -> Dict[str, Any]:
    out = {"ok": True}
    out.update(k)
    return out


def _fail(code: str, message: str, **k: Any) -> Dict[str, Any]:
    out = {"ok": False, "error": code, "message": message}
    out.update(k)
    return out


# ------------------------------------------------------------
# Core helpers
# ------------------------------------------------------------
def _rpc_read(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Returns the subscription row as a dict, or None if not found.
    This calls the stable RPC to avoid PostgREST schema cache issues.
    """
    try:
        res = supabase.rpc(RPC_READ, {"p_account_id": account_id}).execute()
        data = getattr(res, "data", None)
        if not data:
            return None

        # Some Supabase client versions return jsonb as dict directly; others as list.
        if isinstance(data, list):
            return data[0] if data else None
        if isinstance(data, dict):
            # RPC returns to_jsonb(us) -> dict of row fields
            return data
        return None
    except Exception:
        return None


def _rpc_activate(account_id: str, plan_code: str, days: int) -> Dict[str, Any]:
    """
    Calls bms_activate_subscription(account_id, plan_code, days) and returns response dict.
    """
    try:
        payload = {"p_account_id": account_id, "p_plan_code": plan_code, "p_days": days}
        res = supabase.rpc(RPC_ACTIVATE, payload).execute()
        data = getattr(res, "data", None)

        # RPC defined in your debug output returns jsonb with account_id/plan_code/current_period_end/row
        return _ok(method="rpc", activated=True, result=data)
    except Exception as e:
        return _fail("rpc_failed", f"RPC activation failed: {e!s}")


# ------------------------------------------------------------
# Public API (imported by routes)
# ------------------------------------------------------------
def activate_subscription_now(*, account_id: str, plan_code: str = "monthly", days: Any = None) -> Dict[str, Any]:
    """
    Admin/manual activation endpoint uses this.
    MUST exist because app.routes.subscriptions imports it.
    """
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip() or "monthly"
    d = _as_int(days, DEFAULT_DAYS)

    if not account_id:
        return _fail("bad_request", "account_id is required")
    if d <= 0:
        return _fail("bad_request", "days must be > 0")

    out = _rpc_activate(account_id, plan_code, d)
    if not out.get("ok"):
        return out

    # Normalize a friendly subset for callers
    # (your route prints: account_id / plan_code / status / current_period_end)
    row = None
    data = out.get("result")
    if isinstance(data, dict):
        row = data.get("row") if isinstance(data.get("row"), dict) else None

    # Fall back: read again via RPC if row missing
    if row is None:
        row = _rpc_read(account_id) or {}

    current_period_end = row.get("current_period_end") or (data.get("current_period_end") if isinstance(data, dict) else None)

    return _ok(
        activated=True,
        method="rpc",
        account_id=account_id,
        plan_code=row.get("plan_code") or plan_code,
        status=row.get("status") or "active",
        current_period_end=current_period_end,
        result={
            "account_id": account_id,
            "plan_code": row.get("plan_code") or plan_code,
            "status": row.get("status") or "active",
            "current_period_end": current_period_end,
        },
        request_id=out.get("request_id"),
    )


def get_subscription_status(*, account_id: str) -> Dict[str, Any]:
    """
    MUST exist because ask_service imports it and routes call it.
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("bad_request", "account_id is required")

    row = _rpc_read(account_id)

    # If no row, treat as free/inactive
    if not row:
        return _ok(
            account_id=account_id,
            plan_code=DEFAULT_PLAN_CODE,
            status="inactive",
            active=False,
            current_period_end=None,
        )

    end = row.get("current_period_end")
    active = (row.get("status") or "").lower() == "active"
    # If end exists and is in the past, consider inactive (even if status says active)
    try:
        if end:
            # Supabase returns ISO string; parse lightly
            dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
            if dt < _now_utc():
                active = False
    except Exception:
        pass

    return _ok(
        account_id=account_id,
        plan_code=row.get("plan_code") or DEFAULT_PLAN_CODE,
        status=row.get("status") or "inactive",
        active=active,
        current_period_end=end,
    )


def handle_payment_success(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Called by Paystack webhook route.
    Expects payload keys:
      event_id, provider, reference, account_id, plan_code, amount_kobo, currency, upgrade_mode, raw
    """
    account_id = (payload.get("account_id") or "").strip()
    plan_code = (payload.get("plan_code") or "").strip()
    upgrade_mode = (payload.get("upgrade_mode") or "now").strip().lower()
    reference = payload.get("reference")
    event_id = payload.get("event_id")

    if not account_id or not plan_code:
        return _fail("bad_request", "account_id and plan_code are required", seen=payload)

    if upgrade_mode not in ("now", "at_expiry"):
        upgrade_mode = "now"

    # Best-effort idempotency (optional table). If table doesn't exist, we still proceed.
    # If you already have a table, this will prevent double-processing.
    processed_before = False
    try:
        if event_id:
            chk = (
                supabase.table("payment_events")
                .select("event_id")
                .eq("event_id", event_id)
                .limit(1)
                .execute()
            )
            rows = (chk.data or []) if hasattr(chk, "data") else []
            if rows:
                processed_before = True
    except Exception:
        processed_before = False

    if processed_before:
        return _ok(ok=True, processed=True, duplicate=True, account_id=account_id, plan_code=plan_code, reference=reference, upgrade_mode=upgrade_mode)

    # If at_expiry requested, try to store next plan if schema supports it; otherwise activate now.
    if upgrade_mode == "at_expiry":
        stored = False
        try:
            # Try update next_plan_code if column exists
            upd = (
                supabase.table("user_subscriptions")
                .update({"next_plan_code": plan_code, "updated_at": _now_utc().isoformat()})
                .eq("account_id", account_id)
                .execute()
            )
            stored = True
        except Exception:
            stored = False

        if stored:
            # Record event idempotently (best-effort)
            try:
                if event_id:
                    supabase.table("payment_events").insert(
                        {"event_id": event_id, "provider": payload.get("provider"), "reference": reference, "raw": payload.get("raw")}
                    ).execute()
            except Exception:
                pass

            return _ok(
                ok=True,
                processed=True,
                account_id=account_id,
                plan_code=plan_code,
                upgrade_mode="at_expiry",
                queued=True,
                reference=reference,
            )

        # Fallback: activate immediately if we can't store next plan
        upgrade_mode = "now"

    # Activate immediately (RPC-first)
    activation = activate_subscription_now(account_id=account_id, plan_code=plan_code, days=DEFAULT_DAYS)

    # Record event idempotently (best-effort)
    try:
        if event_id:
            supabase.table("payment_events").insert(
                {"event_id": event_id, "provider": payload.get("provider"), "reference": reference, "raw": payload.get("raw")}
            ).execute()
    except Exception:
        pass

    return _ok(
        ok=True,
        processed=True,
        account_id=account_id,
        plan_code=plan_code,
        upgrade_mode="now",
        reference=reference,
        activation=activation,
    )


def expire_overdue_subscriptions() -> Dict[str, Any]:
    """
    Used by optional cron route.
    Expires rows where current_period_end < now() and status='active'.
    MUST exist because app.routes.cron imports it in your boot output.
    """
    try:
        # We do this via table update; if RLS blocks, this should run under service role key.
        now_iso = _now_utc().isoformat()

        # Supabase python uses filters like .lt("col", value)
        res = (
            supabase.table("user_subscriptions")
            .update({"status": "inactive", "updated_at": now_iso})
            .eq("status", "active")
            .lt("current_period_end", now_iso)
            .execute()
        )
        count = len(res.data or []) if hasattr(res, "data") and isinstance(res.data, list) else None
        return _ok(expired=True, count=count)
    except Exception as e:
        return _fail("expire_failed", f"expire_overdue_subscriptions failed: {e!s}")
