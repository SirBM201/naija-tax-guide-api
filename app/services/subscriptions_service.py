# app/services/subscriptions_service.py
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

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


def _rootcause(
    where: str,
    e: Exception,
    *,
    req_id: str,
    hint: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
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


def _fail(
    error: str,
    req_id: str,
    *,
    root_cause: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False, "error": error, "request_id": req_id}
    if root_cause:
        out["root_cause"] = root_cause
    if extra:
        out["extra"] = extra
    return out


def _is_supabase_client_object(x: Any) -> bool:
    # crude but effective: the client has `.table()` method.
    return hasattr(x, "table") and callable(getattr(x, "table"))


def _parse_iso_dt(v: Any) -> Optional[datetime]:
    if not v:
        return None
    try:
        s = str(v)
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _days_for_plan(plan_code: str) -> int:
    plan_code = (plan_code or "monthly").strip().lower()
    if plan_code == "monthly":
        return 30
    if plan_code == "quarterly":
        return 90
    if plan_code == "yearly":
        return 365
    raise ValueError(f"invalid plan_code: {plan_code}")


def _recommended_sql_pack() -> Dict[str, str]:
    """
    Copy-paste SQL to permanently fix schema + enable RPC (bypasses PostgREST schema cache headaches).
    """
    sql_table = r"""
-- Ensure table exists with the exact columns our API expects
create table if not exists public.user_subscriptions (
  account_id uuid primary key,
  plan_code text not null default 'free',
  status text not null default 'inactive',
  current_period_end timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Helpful index
create index if not exists idx_user_subscriptions_status on public.user_subscriptions(status);

-- Keep updated_at fresh
create or replace function public.bms_touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end $$;

drop trigger if exists trg_user_subscriptions_touch on public.user_subscriptions;
create trigger trg_user_subscriptions_touch
before update on public.user_subscriptions
for each row execute function public.bms_touch_updated_at();
""".strip()

    sql_rpc = r"""
-- RPC READ (stable)
create or replace function public.bms_read_subscription(p_account_id uuid)
returns jsonb
language sql
stable
as $$
  select to_jsonb(us)
  from public.user_subscriptions us
  where us.account_id = p_account_id
  limit 1;
$$;

-- RPC ACTIVATE (permanent bypass of PostgREST schema cache)
create or replace function public.bms_activate_subscription(
  p_account_id uuid,
  p_plan_code text,
  p_days int
)
returns jsonb
language plpgsql
security definer
as $$
declare
  v_end timestamptz;
  v_row jsonb;
begin
  v_end := now() + make_interval(days => p_days);

  insert into public.user_subscriptions (account_id, plan_code, status, current_period_end, created_at, updated_at)
  values (p_account_id, p_plan_code, 'active', v_end, now(), now())
  on conflict (account_id) do update
    set plan_code = excluded.plan_code,
        status = excluded.status,
        current_period_end = excluded.current_period_end,
        updated_at = now();

  select to_jsonb(us) into v_row
  from public.user_subscriptions us
  where us.account_id = p_account_id
  limit 1;

  return jsonb_build_object(
    'account_id', p_account_id,
    'plan_code', p_plan_code,
    'current_period_end', v_end,
    'row', v_row
  );
end $$;

-- IMPORTANT: allow your service role / API roles to execute the RPC
grant execute on function public.bms_read_subscription(uuid) to anon, authenticated, service_role;
grant execute on function public.bms_activate_subscription(uuid, text, int) to service_role;
""".strip()

    return {"table_and_trigger.sql": sql_table, "rpc.sql": sql_rpc}


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
                "message": "supabase import is not a client object (no .table method).",
                "request_id": req_id,
                "hint": "Ensure app.core.supabase_client exports `supabase = create_client(...)`, not a function.",
            },
        )

    try:
        use_rpc = _env_bool("SUBS_USE_RPC", True)

        if use_rpc:
            try:
                r = supabase.rpc("bms_read_subscription", {"p_account_id": account_id}).execute()
                row = (r.data or None) if hasattr(r, "data") else None
                # NOTE: our bms_read_subscription returns jsonb row (or null)
                # Normalize paid logic:
                is_active = False
                if isinstance(row, dict):
                    status = (row.get("status") or "").lower()
                    cpe = _parse_iso_dt(row.get("current_period_end"))
                    if status in {"active", "paid"}:
                        is_active = True
                    if cpe and cpe > _now_utc():
                        is_active = True
                return _ok({"subscription": row, "is_paid": is_active, "method": "rpc"}, req_id)
            except Exception:
                pass  # fall back to table read

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
        if isinstance(row, dict):
            status = (row.get("status") or "").lower()
            cpe = _parse_iso_dt(row.get("current_period_end"))
            if status in {"active", "paid"}:
                is_active = True
            if cpe and cpe > _now_utc():
                is_active = True

        return _ok({"subscription": row, "is_paid": is_active, "method": "table_select"}, req_id)

    except Exception as e:
        return _fail(
            "get_subscription_status_failed",
            req_id,
            root_cause=_rootcause(
                "subscriptions_service.get_subscription_status",
                e,
                req_id=req_id,
                hint="DB read failed. If you see PGRST204, PostgREST schema cache sees different columns than your DB.",
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
            days = _days_for_plan(plan_code)
        else:
            days = int(days)

        use_rpc = _env_bool("SUBS_USE_RPC", True)
        rpc_err: Optional[str] = None

        if use_rpc:
            try:
                r = supabase.rpc(
                    "bms_activate_subscription",
                    {"p_account_id": account_id, "p_plan_code": plan_code, "p_days": days},
                ).execute()
                data = r.data if hasattr(r, "data") else None
                return _ok({"activated": True, "method": "rpc", "result": data}, req_id)
            except Exception as e:
                rpc_err = str(e)

        # Fallback: direct upsert (can fail if schema cache mismatch)
        current_period_end = (_now_utc() + timedelta(days=days)).isoformat()

        payload = {
            "account_id": account_id,
            "plan_code": plan_code,
            "status": "active",
            "current_period_end": current_period_end,
            "updated_at": _now_utc().isoformat(),
        }

        res = supabase.table("user_subscriptions").upsert(payload, on_conflict="account_id").execute()
        return _ok(
            {
                "activated": True,
                "method": "table_upsert",
                "row": getattr(res, "data", None),
                "rpc_error": rpc_err,
            },
            req_id,
        )

    except Exception as e:
        hint = (
            "If you see PGRST204 missing 'current_period_end', PostgREST schema cache is stale or your DB schema differs. "
            "Permanent fix: create RPC functions (bms_activate_subscription + bms_read_subscription) and use service role key."
        )
        return _fail(
            "activate_subscription_failed",
            req_id,
            root_cause=_rootcause(
                "subscriptions_service.activate_subscription_now",
                e,
                req_id=req_id,
                hint=hint,
                extra={"account_id": account_id, "plan_code": plan_code, "days": days},
            ),
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
        try:
            r = supabase.rpc("bms_read_subscription", {"p_account_id": account_id}).execute()
            row = (r.data or None) if hasattr(r, "data") else None
            return _ok({"row": row, "method": "rpc"}, req_id)
        except Exception:
            pass

        res = supabase.table("user_subscriptions").select("*").eq("account_id", account_id).limit(1).execute()
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
                hint="If you get PGRST204, schema cache/columns are mismatched. Install RPC + run SQL migration.",
                extra={"account_id": account_id},
            ),
        )


def debug_expose_subscription_health(account_id: Optional[str] = None) -> Dict[str, Any]:
    """
    OUT-OF-THE-BOX debugger exposer:
    - confirms supabase client shape
    - probes RPC functions
    - probes table access
    - returns concrete SQL for permanent fix
    """
    req_id = str(uuid.uuid4())

    sql_pack = _recommended_sql_pack()
    info: Dict[str, Any] = {
        "client_ok": _is_supabase_client_object(supabase),
        "rpc_probe": {},
        "table_probe": {},
        "diagnosis": [],
        "recommended_sql_files": sql_pack,  # <-- copy-paste ready SQL
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

    # Probe RPC
    try:
        probe_id = account_id or "00000000-0000-0000-0000-000000000000"
        r = supabase.rpc("bms_read_subscription", {"p_account_id": probe_id}).execute()
        info["rpc_probe"] = {"ok": True, "data": r.data if hasattr(r, "data") else None}
    except Exception as e:
        msg = str(e)
        info["rpc_probe"] = {"ok": False, "error": msg}
        info["diagnosis"].append("RPC bms_read_subscription not installed OR no execute permission. Install rpc.sql.")

    # Probe table
    try:
        res = supabase.table("user_subscriptions").select("*").limit(1).execute()
        info["table_probe"] = {"ok": True, "sample": getattr(res, "data", None)}
    except Exception as e:
        msg = str(e)
        info["table_probe"] = {"ok": False, "error": msg}
        if "PGRST204" in msg:
            info["diagnosis"].append("PostgREST schema cache mismatch (PGRST204). RPC activation avoids this permanently.")
        if "permission" in msg.lower():
            info["diagnosis"].append("Permission issue: ensure backend uses SUPABASE_SERVICE_ROLE_KEY for admin writes.")

    # Always include permanent recommendation
    info["diagnosis"].append("Permanent fix: use RPC bms_activate_subscription for activation; keep table schema stable.")

    return _ok(info, req_id)


# ---------------------------
# Webhook-facing functions (MUST exist if routes import them)
# ---------------------------
def handle_payment_success(
    *,
    account_id: str,
    plan_code: str,
    paid_days: Optional[int] = None,
    provider: str = "paystack",
    provider_ref: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Called by app.routes.webhooks.
    Keeps boot stable + makes subscription activation consistent.
    """
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)

    try:
        days = int(paid_days) if paid_days is not None else _days_for_plan(plan_code)
        # Reuse activation logic (prefer RPC)
        r = activate_subscription_now(account_id=account_id, plan_code=plan_code, days=days)
        # Add webhook context (doesn't break existing consumer code)
        r.setdefault("webhook", {})
        r["webhook"].update(
            {
                "provider": provider,
                "provider_ref": provider_ref,
                "event": "payment_success",
            }
        )
        r.setdefault("request_id", req_id)
        return r
    except Exception as e:
        return _fail(
            "handle_payment_success_failed",
            req_id,
            root_cause=_rootcause(
                "subscriptions_service.handle_payment_success",
                e,
                req_id=req_id,
                hint="Webhook success handler crashed. Check payload mapping for account_id/plan_code.",
                extra={"account_id": account_id, "plan_code": plan_code, "provider": provider, "provider_ref": provider_ref},
            ),
        )


def handle_payment_failed(
    *,
    account_id: str,
    provider: str = "paystack",
    provider_ref: Optional[str] = None,
    reason: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Safe handler so imports never break even if you later implement full logic.
    """
    req_id = str(uuid.uuid4())
    return _ok(
        {
            "handled": True,
            "event": "payment_failed",
            "account_id": account_id,
            "provider": provider,
            "provider_ref": provider_ref,
            "reason": reason,
        },
        req_id,
    )
