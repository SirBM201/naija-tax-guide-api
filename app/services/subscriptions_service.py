# app/services/subscriptions_service.py
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase  # must be a CLIENT, not a function


# ---------------------------
# Helpers
# ---------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env_bool(name: str, default: bool = False) -> bool:
    v = (os.getenv(name) or "").strip().lower()
    if v == "":
        return default
    return v in {"1", "true", "yes", "y", "on"}


def _rootcause(where: str, e: Exception, *, req_id: str, hint: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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


def _ok(payload: Dict[str, Any], req_id: str) -> Dict[str, Any]:
    payload["ok"] = True
    payload.setdefault("request_id", req_id)
    return payload


def _fail(error: str, req_id: str, *, root_cause: Optional[Dict[str, Any]] = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False, "error": error, "request_id": req_id}
    if root_cause:
        out["root_cause"] = root_cause
    if extra:
        out["extra"] = extra
    return out


def _is_supabase_client_object(x: Any) -> bool:
    # crude but effective: the client has `.table()` method.
    return hasattr(x, "table") and callable(getattr(x, "table"))


# ---------------------------
# Public API (imported by routes + ask_service)
# ---------------------------
def get_subscription_status(account_id: str) -> Dict[str, Any]:
    """
    Used by ask_service.
    Returns a normalized subscription state.
    Never throws; always returns ok/fail payload.
    """
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)

    if not _is_supabase_client_object(supabase):
        return _fail(
            "supabase_client_invalid",
            req_id,
            root_cause={
                "where": "subscriptions_service.get_subscription_status",
                "type": "ConfigError",
                "message": "supabase import is not a client object (no .table method). Check app/core/supabase_client.py export.",
                "request_id": req_id,
                "hint": "Ensure app.core.supabase_client exports `supabase = create_client(...)`, not a function.",
            },
        )

    try:
        # Prefer RPC-based read if available (more stable when schema cache is weird)
        use_rpc = _env_bool("SUBS_USE_RPC", True)

        if use_rpc:
            try:
                r = supabase.rpc("bms_read_subscription", {"p_account_id": account_id}).execute()
                row = (r.data or None) if hasattr(r, "data") else None
                # bms_read_subscription returns either NULL or json row
                return _ok({"subscription": row, "is_paid": bool(row and row.get("is_active"))}, req_id)
            except Exception:
                # fall back to table select
                pass

        res = (
            supabase.table("user_subscriptions")
            .select("account_id, plan_code, status, current_period_end, created_at, updated_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        row = rows[0] if rows else None

        is_active = False
        if row:
            cpe = row.get("current_period_end")
            status = (row.get("status") or "").lower()
            if status in {"active", "paid"}:
                is_active = True
            if cpe:
                # if current_period_end is in the future, active
                try:
                    # supabase usually returns ISO string
                    dt = datetime.fromisoformat(str(cpe).replace("Z", "+00:00"))
                    if dt > _now_utc():
                        is_active = True
                except Exception:
                    pass

        return _ok({"subscription": row, "is_paid": is_active}, req_id)

    except Exception as e:
        return _fail(
            "get_subscription_status_failed",
            req_id,
            root_cause=_rootcause(
                "subscriptions_service.get_subscription_status",
                e,
                req_id=req_id,
                hint="DB read failed. If you see PGRST204, your table schema is missing columns or PostgREST schema cache is stale.",
                extra={"account_id": account_id},
            ),
        )


def activate_subscription_now(account_id: str, plan_code: str = "monthly", days: Optional[int] = None) -> Dict[str, Any]:
    """
    Admin-only activation.
    Permanent approach:
    - Prefer RPC function (SECURITY DEFINER) => avoids PostgREST schema-cache/column mismatch issues
    - Fall back to table upsert only if RPC missing
    """
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)

    if not _is_supabase_client_object(supabase):
        return _fail(
            "supabase_client_invalid",
            req_id,
            root_cause={
                "where": "subscriptions_service.activate_subscription_now",
                "type": "ConfigError",
                "message": "supabase import is not a client object (no .table method).",
                "request_id": req_id,
                "hint": "Fix app/core/supabase_client.py export.",
            },
        )

    try:
        plan_code = (plan_code or "monthly").strip().lower()
        if plan_code not in {"monthly", "quarterly", "yearly"}:
            return _fail("invalid_plan_code", req_id, extra={"plan_code": plan_code})

        if days is None:
            days = {"monthly": 30, "quarterly": 90, "yearly": 365}[plan_code]
        else:
            days = int(days)

        use_rpc = _env_bool("SUBS_USE_RPC", True)

        # 1) Preferred: RPC upsert (permanent fix)
        if use_rpc:
            try:
                r = supabase.rpc(
                    "bms_activate_subscription",
                    {"p_account_id": account_id, "p_plan_code": plan_code, "p_days": days},
                ).execute()
                data = r.data if hasattr(r, "data") else None
                return _ok({"activated": True, "method": "rpc", "result": data}, req_id)
            except Exception as e:
                # If RPC not installed, we'll fall back, but we also return the RPC error in root cause
                rpc_err = str(e)

        # 2) Fallback: direct upsert (may fail with PGRST204)
        current_period_end = (_now_utc() + timedelta(days=days)).isoformat()

        payload = {
            "account_id": account_id,
            "plan_code": plan_code,
            "status": "active",
            "current_period_end": current_period_end,
            "updated_at": _now_utc().isoformat(),
        }

        res = (
            supabase.table("user_subscriptions")
            .upsert(payload, on_conflict="account_id")
            .execute()
        )

        return _ok({"activated": True, "method": "table_upsert", "row": getattr(res, "data", None)}, req_id)

    except Exception as e:
        msg = str(e)
        hint = (
            "If you see PGRST204 missing 'current_period_end', your table is missing that column OR PostgREST schema cache hasn't reloaded. "
            "Permanent fix is to install bms_activate_subscription RPC + add required columns (SQL provided by debug endpoint)."
        )
        extra = {"account_id": account_id, "plan_code": plan_code, "days": days}

        # Include rpc failure if it happened
        if "rpc_err" in locals():
            extra["rpc_error"] = rpc_err

        return _fail(
            "activate_subscription_failed",
            req_id,
            root_cause=_rootcause("subscriptions_service.activate_subscription_now", e, req_id=req_id, hint=hint, extra=extra),
        )


def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    """
    Used by /_debug/subscription endpoint.
    Returns row OR null, never crashes.
    """
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)

    if not _is_supabase_client_object(supabase):
        return _fail("supabase_client_invalid", req_id)

    try:
        # Prefer RPC read if available
        try:
            r = supabase.rpc("bms_read_subscription", {"p_account_id": account_id}).execute()
            row = (r.data or None) if hasattr(r, "data") else None
            return _ok({"row": row, "method": "rpc"}, req_id)
        except Exception:
            pass

        res = (
            supabase.table("user_subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        return _ok({"row": (rows[0] if rows else None), "method": "table_select"}, req_id)

    except Exception as e:
        return _fail(
            "debug_read_subscription_failed",
            req_id,
            root_cause=_rootcause(
                "subscriptions_service.debug_read_subscription",
                e,
                req_id=req_id,
                hint="If you get PGRST204, your schema cache/columns are mismatched. Install RPC + run SQL migration.",
                extra={"account_id": account_id},
            ),
        )


def debug_expose_subscription_health(account_id: Optional[str] = None) -> Dict[str, Any]:
    """
    OUT-OF-THE-BOX debugger exposer:
    - confirms supabase client shape
    - confirms RPC exists (by calling it)
    - returns recommended SQL migration if errors suggest missing columns
    """
    req_id = str(uuid.uuid4())

    info: Dict[str, Any] = {
        "client_ok": _is_supabase_client_object(supabase),
        "rpc_probe": {},
        "table_probe": {},
        "recommended_sql": [],
    }

    if not info["client_ok"]:
        return _fail(
            "supabase_client_invalid",
            req_id,
            root_cause={
                "where": "subscriptions_service.debug_expose_subscription_health",
                "type": "ConfigError",
                "message": "supabase is not a client object (no .table).",
                "request_id": req_id,
                "hint": "Fix app/core/supabase_client.py to export `supabase = create_client(...)`.",
            },
        )

    # Probe RPC install
    try:
        # This should succeed if function exists, even if account_id is nonsense (returns null)
        r = supabase.rpc("bms_read_subscription", {"p_account_id": account_id or "00000000-0000-0000-0000-000000000000"}).execute()
        info["rpc_probe"] = {"ok": True, "data": r.data if hasattr(r, "data") else None}
    except Exception as e:
        info["rpc_probe"] = {"ok": False, "error": str(e)}
        info["recommended_sql"].append("Install RPC functions bms_read_subscription + bms_activate_subscription (see SQL below).")

    # Probe table + common columns
    try:
        res = supabase.table("user_subscriptions").select("*").limit(1).execute()
        info["table_probe"] = {"ok": True, "sample": getattr(res, "data", None)}
    except Exception as e:
        msg = str(e)
        info["table_probe"] = {"ok": False, "error": msg}
        if "PGRST204" in msg and "current_period_end" in msg:
            info["recommended_sql"].append("Add missing column current_period_end to public.user_subscriptions and reload schema cache.")
        if "permission" in msg.lower():
            info["recommended_sql"].append("Backend is likely not using service role key for DB operations.")

    # Always include the “permanent SQL” suggestion
    info["recommended_sql"].append("Use RPC-based activation to avoid PostgREST schema-cache issues permanently.")

    return _ok(info, req_id)
