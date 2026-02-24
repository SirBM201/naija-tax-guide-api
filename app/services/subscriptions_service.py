# app/services/subscriptions_service.py
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

from app.core.supabase_client import supabase  # must be a CLIENT object


# =============================================================================
# Helpers (safe, never crash)
# =============================================================================
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _env_bool(name: str, default: bool = False) -> bool:
    v = (os.getenv(name) or "").strip().lower()
    if v == "":
        return default
    return v in {"1", "true", "yes", "y", "on"}


def _is_supabase_client_object(x: Any) -> bool:
    return hasattr(x, "table") and callable(getattr(x, "table"))


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


def _parse_iso_dt(v: Any) -> Optional[datetime]:
    if not v:
        return None
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except Exception:
        return None


def _normalize_plan(plan_code: str) -> str:
    p = (plan_code or "").strip().lower()
    if p in {"monthly", "quarterly", "yearly"}:
        return p
    return "monthly"


def _days_for_plan(plan_code: str) -> int:
    p = _normalize_plan(plan_code)
    return {"monthly": 30, "quarterly": 90, "yearly": 365}[p]


def _safe_rpc(name: str, params: Dict[str, Any]) -> Tuple[bool, Any, Optional[str]]:
    """
    Returns (ok, data, error_string)
    """
    try:
        r = supabase.rpc(name, params).execute()
        data = r.data if hasattr(r, "data") else None
        return True, data, None
    except Exception as e:
        return False, None, str(e)


# =============================================================================
# Public API (imported by routes + ask_service)
# =============================================================================
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
        use_rpc = _env_bool("SUBS_USE_RPC", True)

        # 1) Preferred: RPC read
        if use_rpc:
            ok, data, err = _safe_rpc("bms_read_subscription", {"p_account_id": account_id})
            if ok:
                row = data or None  # function returns jsonb or null
                is_active = bool(row and (row.get("status") in {"active", "paid"}))
                cpe = _parse_iso_dt(row.get("current_period_end") if row else None)
                if cpe and cpe > _now_utc():
                    is_active = True
                return _ok({"subscription": row, "is_paid": is_active, "method": "rpc"}, req_id)

        # 2) Fallback: table select
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
                hint="DB read failed. If you see PGRST204, PostgREST schema cache or columns are mismatched. Prefer RPC functions.",
                extra={"account_id": account_id},
            ),
        )


def activate_subscription_now(account_id: str, plan_code: str = "monthly", days: Optional[int] = None) -> Dict[str, Any]:
    """
    Admin-only activation.
    Preferred: RPC (bms_activate_subscription)
    Fallback: upsert user_subscriptions
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
        plan_code = _normalize_plan(plan_code)
        days = _days_for_plan(plan_code) if days is None else int(days)

        use_rpc = _env_bool("SUBS_USE_RPC", True)

        # 1) Preferred: RPC activation
        if use_rpc:
            ok, data, err = _safe_rpc(
                "bms_activate_subscription",
                {"p_account_id": account_id, "p_plan_code": plan_code, "p_days": days},
            )
            if ok:
                return _ok({"activated": True, "method": "rpc", "result": data}, req_id)

        # 2) Fallback: direct upsert
        current_period_end = (_now_utc() + timedelta(days=days)).isoformat()
        payload = {
            "account_id": account_id,
            "plan_code": plan_code,
            "status": "active",
            "current_period_end": current_period_end,
            "updated_at": _now_utc().isoformat(),
        }

        res = supabase.table("user_subscriptions").upsert(payload, on_conflict="account_id").execute()
        return _ok({"activated": True, "method": "table_upsert", "row": getattr(res, "data", None)}, req_id)

    except Exception as e:
        return _fail(
            "activate_subscription_failed",
            req_id,
            root_cause=_rootcause(
                "subscriptions_service.activate_subscription_now",
                e,
                req_id=req_id,
                hint=(
                    "If you see PGRST204 missing columns, your table is missing columns OR PostgREST schema cache is stale. "
                    "Permanent fix is RPC bms_activate_subscription + stable table schema."
                ),
                extra={"account_id": account_id, "plan_code": plan_code, "days": days},
            ),
        )


# =============================================================================
# Webhook payment handling (Paystack)
# =============================================================================
def handle_payment_success(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Called by app.routes.webhooks on paystack charge.success.

    Expected event keys:
      - provider: "paystack"
      - event_id: str (optional)
      - reference: str (paystack reference)
      - account_id: uuid str
      - plan_code: monthly|quarterly|yearly
      - amount_kobo: int (optional)
      - currency: str (optional)
      - upgrade_mode: "now"|"at_expiry" (optional)
      - raw: full event payload (optional)

    Behavior:
      - idempotency best-effort (if a table exists)
      - if upgrade_mode == "now": activate immediately
      - if upgrade_mode == "at_expiry": try to schedule in a table if exists; otherwise fallback to immediate activation
    """
    req_id = str(uuid.uuid4())

    if not _is_supabase_client_object(supabase):
        return _fail("supabase_client_invalid", req_id)

    provider = (event.get("provider") or "paystack").strip().lower()
    reference = (event.get("reference") or "").strip()
    account_id = (event.get("account_id") or "").strip()
    plan_code = _normalize_plan(str(event.get("plan_code") or "monthly"))
    upgrade_mode = (event.get("upgrade_mode") or "now").strip().lower()
    if upgrade_mode not in {"now", "at_expiry"}:
        upgrade_mode = "now"

    if not account_id or not reference:
        return _fail("missing_account_or_reference", req_id, extra={"account_id": account_id, "reference": reference})

    # -------------------------------------------------------------------------
    # 1) Idempotency (BEST EFFORT)
    # -------------------------------------------------------------------------
    # If you create this table, duplicates become impossible:
    #   create table public.payment_events (
    #     provider text not null,
    #     reference text not null,
    #     event_id text null,
    #     account_id uuid not null,
    #     created_at timestamptz not null default now(),
    #     raw jsonb null,
    #     primary key (provider, reference)
    #   );
    #
    # But we will NOT require it; we just try.
    already_processed = False
    try:
        res = (
            supabase.table("payment_events")
            .select("provider, reference")
            .eq("provider", provider)
            .eq("reference", reference)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        already_processed = bool(rows)
    except Exception:
        # table may not exist; ignore
        already_processed = False

    if already_processed:
        return _ok(
            {
                "processed": True,
                "idempotent": True,
                "message": "Payment reference already processed.",
                "reference": reference,
                "account_id": account_id,
                "plan_code": plan_code,
            },
            req_id,
        )

    # -------------------------------------------------------------------------
    # 2) Apply subscription change
    # -------------------------------------------------------------------------
    try:
        if upgrade_mode == "now":
            act = activate_subscription_now(account_id, plan_code=plan_code, days=_days_for_plan(plan_code))
            if not act.get("ok"):
                return _fail("payment_applied_failed", req_id, extra={"activation": act})

            _record_payment_event_best_effort(provider, reference, event, account_id)
            return _ok(
                {
                    "processed": True,
                    "upgrade_mode": upgrade_mode,
                    "activation": act,
                    "reference": reference,
                    "account_id": account_id,
                    "plan_code": plan_code,
                },
                req_id,
            )

        # upgrade_mode == "at_expiry"
        # Attempt to schedule (if you have a table). If not available, fallback.
        scheduled = _schedule_change_best_effort(account_id, plan_code, reference, event)
        if scheduled.get("scheduled"):
            _record_payment_event_best_effort(provider, reference, event, account_id)
            return _ok(
                {
                    "processed": True,
                    "upgrade_mode": upgrade_mode,
                    "scheduled": True,
                    "schedule": scheduled,
                    "reference": reference,
                    "account_id": account_id,
                    "plan_code": plan_code,
                },
                req_id,
            )

        # Fallback if scheduling not possible
        act = activate_subscription_now(account_id, plan_code=plan_code, days=_days_for_plan(plan_code))
        if not act.get("ok"):
            return _fail("payment_applied_failed", req_id, extra={"activation": act, "schedule": scheduled})

        _record_payment_event_best_effort(provider, reference, event, account_id)
        return _ok(
            {
                "processed": True,
                "upgrade_mode": "now_fallback",
                "activation": act,
                "schedule": scheduled,
                "reference": reference,
                "account_id": account_id,
                "plan_code": plan_code,
            },
            req_id,
        )

    except Exception as e:
        return _fail(
            "handle_payment_success_failed",
            req_id,
            root_cause=_rootcause(
                "subscriptions_service.handle_payment_success",
                e,
                req_id=req_id,
                hint="Webhook handling failed. Check DB permissions and table availability.",
                extra={"provider": provider, "reference": reference, "account_id": account_id, "plan_code": plan_code},
            ),
        )


def _record_payment_event_best_effort(provider: str, reference: str, raw_event: Dict[str, Any], account_id: str) -> None:
    try:
        payload = {
            "provider": provider,
            "reference": reference,
            "event_id": raw_event.get("event_id"),
            "account_id": account_id,
            "raw": raw_event.get("raw") or raw_event,
        }
        supabase.table("payment_events").upsert(payload, on_conflict="provider,reference").execute()
    except Exception:
        # optional
        return


def _schedule_change_best_effort(account_id: str, plan_code: str, reference: str, raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Best-effort scheduler. Only works if you create the table:
      create table public.subscription_changes (
        id uuid primary key default gen_random_uuid(),
        account_id uuid not null,
        plan_code text not null,
        reference text not null,
        status text not null default 'scheduled',
        created_at timestamptz not null default now(),
        raw jsonb null
      );
      create unique index if not exists uq_subscription_changes_ref on public.subscription_changes(reference);
    """
    try:
        payload = {
            "account_id": account_id,
            "plan_code": plan_code,
            "reference": reference,
            "status": "scheduled",
            "raw": raw_event.get("raw") or raw_event,
        }
        supabase.table("subscription_changes").insert(payload).execute()
        return {"scheduled": True, "method": "subscription_changes_table"}
    except Exception as e:
        return {"scheduled": False, "method": "fallback", "error": str(e)}


# =============================================================================
# Debug helpers (used by /_debug/subscription_health)
# =============================================================================
def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)

    if not _is_supabase_client_object(supabase):
        return _fail("supabase_client_invalid", req_id)

    try:
        # Prefer RPC read
        ok, data, err = _safe_rpc("bms_read_subscription", {"p_account_id": account_id})
        if ok:
            return _ok({"row": data or None, "method": "rpc"}, req_id)

        # Fallback table read
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
                hint="If you get PGRST204, schema cache/columns mismatched. Use RPC + stable table schema.",
                extra={"account_id": account_id},
            ),
        )


def debug_expose_subscription_health(account_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Used by /api/_debug/subscription_health (admin-gated in routes).
    Confirms:
      - supabase client shape
      - RPC callable
      - table readable
      - returns recommended SQL files for stability
    """
    req_id = str(uuid.uuid4())

    info: Dict[str, Any] = {
        "client_ok": _is_supabase_client_object(supabase),
        "diagnosis": [],
        "hints": {},
        "rpc_probe": {},
        "table_probe": {},
        "recommended_sql_files": {},
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
    probe_id = account_id or "00000000-0000-0000-0000-000000000000"
    ok, data, err = _safe_rpc("bms_read_subscription", {"p_account_id": probe_id})
    if ok:
        info["rpc_probe"] = {"ok": True, "data": data}
        info["diagnosis"].append("RPC bms_read_subscription is callable (good).")
    else:
        info["rpc_probe"] = {"ok": False, "error": err}
        info["diagnosis"].append("RPC bms_read_subscription NOT callable (install recommended).")

    # Probe table
    try:
        res = supabase.table("user_subscriptions").select("*").limit(1).execute()
        rows = (res.data or []) if hasattr(res, "data") else []
        info["table_probe"] = {"ok": True, "sample_count": len(rows), "sample_keys": list(rows[0].keys()) if rows else []}
        info["diagnosis"].append("Table user_subscriptions is readable via PostgREST (good).")
    except Exception as e:
        msg = str(e)
        info["table_probe"] = {"ok": False, "error": msg}
        info["diagnosis"].append("Table user_subscriptions NOT readable via PostgREST.")
        if "permission" in msg.lower():
            info["hints"]["permission"] = "Backend likely not using service role key or RLS blocks reads."
        if "PGRST204" in msg:
            info["hints"]["schema_cache"] = "PostgREST schema cache/columns mismatched; use RPC + stable schema."

    # Always include permanent guidance + SQL
    info["diagnosis"].append("Permanent fix: use RPC bms_activate_subscription for activation; keep table schema stable.")

    rpc_sql = """-- RPC READ (stable)
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
"""

    table_sql = """-- Ensure table exists with the exact columns our API expects
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
"""

    info["recommended_sql_files"] = {"rpc.sql": rpc_sql, "table_and_trigger.sql": table_sql}
    return _ok(info, req_id)
