# app/services/subscriptions_service.py
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

from app.core.supabase_client import supabase  # must be a CLIENT instance


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
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
    message: Optional[str] = None,
    root_cause: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False, "error": error, "request_id": req_id}
    if message:
        out["message"] = message
    if root_cause:
        out["root_cause"] = root_cause
    if extra:
        out["extra"] = extra
    return out


def _plan_days(plan_code: str) -> int:
    plan_code = (plan_code or "").strip().lower()
    return {"monthly": 30, "quarterly": 90, "yearly": 365}.get(plan_code, 30)


def _looks_like_pgrst204(msg: str) -> bool:
    return "PGRST204" in (msg or "")


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
def get_subscription_status(account_id: str) -> Dict[str, Any]:
    """
    Used by ask_service.
    Returns:
      { ok: bool, is_paid: bool, subscription: row_or_null, request_id: str, ... }
    Never throws.
    """
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)

    if not _is_supabase_client_object(supabase):
        return _fail(
            "supabase_client_invalid",
            req_id,
            message="supabase import is not a client object (no .table).",
            root_cause={
                "where": "subscriptions_service.get_subscription_status",
                "type": "ConfigError",
                "message": "supabase is not a client object (no .table).",
                "hint": "Ensure app/core/supabase_client.py exports `supabase = create_client(...)`.",
                "request_id": req_id,
            },
        )

    try:
        use_rpc = _env_bool("SUBS_USE_RPC", True)

        # 1) Prefer RPC read (stable, bypasses PostgREST schema-cache mismatch headaches)
        if use_rpc:
            try:
                r = supabase.rpc("bms_read_subscription", {"p_account_id": account_id}).execute()
                row = (r.data or None) if hasattr(r, "data") else None
                is_active = bool(row and (row.get("status") or "").lower() in {"active", "paid"})
                # If current_period_end exists and is future => active
                if row and row.get("current_period_end"):
                    try:
                        dt = datetime.fromisoformat(str(row["current_period_end"]).replace("Z", "+00:00"))
                        if dt > _now_utc():
                            is_active = True
                    except Exception:
                        pass
                return _ok({"subscription": row, "is_paid": is_active, "method": "rpc"}, req_id)
            except Exception:
                # fall back to table select
                pass

        # 2) Fallback table read
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
            cpe = row.get("current_period_end")
            if status in {"active", "paid"}:
                is_active = True
            if cpe:
                try:
                    dt = datetime.fromisoformat(str(cpe).replace("Z", "+00:00"))
                    if dt > _now_utc():
                        is_active = True
                except Exception:
                    pass

        return _ok({"subscription": row, "is_paid": is_active, "method": "table"}, req_id)

    except Exception as e:
        msg = str(e)
        hint = "DB read failed."
        if _looks_like_pgrst204(msg):
            hint = "PostgREST schema cache mismatch or missing columns. Use RPC bms_read_subscription + ensure table columns exist."
        return _fail(
            "get_subscription_status_failed",
            req_id,
            root_cause=_rootcause(
                "subscriptions_service.get_subscription_status",
                e,
                req_id=req_id,
                hint=hint,
                extra={"account_id": account_id},
            ),
        )


def activate_subscription_now(account_id: str, plan_code: str = "monthly", days: Optional[int] = None) -> Dict[str, Any]:
    """
    Admin activation.
    Permanent strategy:
    - Prefer RPC bms_activate_subscription (SECURITY DEFINER) => bypass schema cache & policy issues.
    - Fallback to table upsert only if RPC unavailable.
    """
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)

    if not _is_supabase_client_object(supabase):
        return _fail(
            "supabase_client_invalid",
            req_id,
            message="supabase import is not a client object (no .table).",
            root_cause={
                "where": "subscriptions_service.activate_subscription_now",
                "type": "ConfigError",
                "message": "supabase is not a client object (no .table).",
                "hint": "Fix app/core/supabase_client.py export.",
                "request_id": req_id,
            },
        )

    try:
        plan_code = (plan_code or "monthly").strip().lower()
        if plan_code not in {"monthly", "quarterly", "yearly"}:
            return _fail("invalid_plan_code", req_id, extra={"plan_code": plan_code})

        days_i = int(days) if days is not None else _plan_days(plan_code)
        use_rpc = _env_bool("SUBS_USE_RPC", True)

        # 1) RPC path (permanent)
        rpc_err: Optional[str] = None
        if use_rpc:
            try:
                r = supabase.rpc(
                    "bms_activate_subscription",
                    {"p_account_id": account_id, "p_plan_code": plan_code, "p_days": days_i},
                ).execute()
                data = r.data if hasattr(r, "data") else None
                return _ok({"activated": True, "method": "rpc", "result": data}, req_id)
            except Exception as e:
                rpc_err = str(e)

        # 2) Fallback upsert path (may fail when PostgREST cache is stale)
        current_period_end = (_now_utc() + timedelta(days=days_i)).isoformat()

        payload = {
            "account_id": account_id,
            "plan_code": plan_code,
            "status": "active",
            "current_period_end": current_period_end,
            "updated_at": _now_utc().isoformat(),
        }

        res = supabase.table("user_subscriptions").upsert(payload, on_conflict="account_id").execute()
        return _ok({"activated": True, "method": "table_upsert", "row": getattr(res, "data", None), "rpc_error": rpc_err}, req_id)

    except Exception as e:
        msg = str(e)
        hint = (
            "Activation failed. Permanent fix is RPC bms_activate_subscription + correct table schema. "
            "If you see PGRST204, your schema cache/columns are mismatched."
        )
        extra = {"account_id": account_id, "plan_code": plan_code, "days": days}
        if "rpc_err" in locals():
            extra["rpc_error"] = locals().get("rpc_err")
        if _looks_like_pgrst204(msg):
            extra["likely_root"] = "PostgREST schema cache mismatch or missing column(s) in user_subscriptions."

        return _fail(
            "activate_subscription_failed",
            req_id,
            root_cause=_rootcause("subscriptions_service.activate_subscription_now", e, req_id=req_id, hint=hint, extra=extra),
        )


def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    """
    Debug read endpoint helper.
    """
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)

    if not _is_supabase_client_object(supabase):
        return _fail("supabase_client_invalid", req_id)

    try:
        # prefer rpc
        try:
            r = supabase.rpc("bms_read_subscription", {"p_account_id": account_id}).execute()
            row = (r.data or None) if hasattr(r, "data") else None
            return _ok({"row": row, "method": "rpc"}, req_id)
        except Exception:
            pass

        res = supabase.table("user_subscriptions").select("*").eq("account_id", account_id).limit(1).execute()
        rows = (res.data or []) if hasattr(res, "data") else []
        return _ok({"row": (rows[0] if rows else None), "method": "table"}, req_id)

    except Exception as e:
        msg = str(e)
        hint = "Debug read failed."
        if _looks_like_pgrst204(msg):
            hint = "Schema cache mismatch/missing columns. Prefer RPC + run schema SQL."
        return _fail(
            "debug_read_subscription_failed",
            req_id,
            root_cause=_rootcause("subscriptions_service.debug_read_subscription", e, req_id=req_id, hint=hint, extra={"account_id": account_id}),
        )


def debug_expose_subscription_health(sample_account_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Debugger exposer:
    - verifies supabase client
    - probes RPC existence
    - probes table select
    - returns ready-to-run SQL strings as 'recommended_sql_files'
    - returns concise diagnosis (PowerShell-friendly: not too deep)
    """
    req_id = str(uuid.uuid4())

    client_ok = _is_supabase_client_object(supabase)
    if not client_ok:
        return _fail(
            "supabase_client_invalid",
            req_id,
            root_cause={
                "where": "subscriptions_service.debug_expose_subscription_health",
                "type": "ConfigError",
                "message": "supabase is not a client object (no .table).",
                "hint": "Fix app/core/supabase_client.py to export `supabase = create_client(...)`.",
                "request_id": req_id,
            },
        )

    acct = (sample_account_id or "00000000-0000-0000-0000-000000000000").strip()

    rpc_probe: Dict[str, Any] = {"ok": False}
    table_probe: Dict[str, Any] = {"ok": False}
    diagnosis: list[str] = []
    hints: list[str] = []

    # --- probe rpc read
    try:
        r = supabase.rpc("bms_read_subscription", {"p_account_id": acct}).execute()
        rpc_probe = {"ok": True, "data": None if not hasattr(r, "data") else r.data}
        diagnosis.append("RPC bms_read_subscription is callable (good).")
    except Exception as e:
        rpc_probe = {"ok": False, "error": str(e)}
        diagnosis.append("RPC bms_read_subscription is NOT callable.")
        hints.append("Run rpc.sql from recommended_sql_files to install RPC functions.")

    # --- probe table select
    try:
        res = supabase.table("user_subscriptions").select("*").limit(1).execute()
        sample = getattr(res, "data", None)
        # keep sample shallow
        table_probe = {"ok": True, "sample_count": len(sample or []), "sample_keys": list((sample or [{}])[0].keys()) if (sample or []) else []}
        diagnosis.append("Table user_subscriptions is readable via PostgREST (good).")
    except Exception as e:
        msg = str(e)
        table_probe = {"ok": False, "error": msg}
        diagnosis.append("Table user_subscriptions probe failed.")
        if _looks_like_pgrst204(msg):
            hints.append("PostgREST schema cache mismatch or missing column(s). Ensure table has current_period_end column (see table_and_trigger.sql).")
        if "permission" in msg.lower() or "jwt" in msg.lower():
            hints.append("Backend likely not using service role for DB writes/reads where required.")

    # Always emphasize permanent approach
    diagnosis.append("Permanent fix: use RPC bms_activate_subscription for activation; keep table schema stable.")

    # Provide SQL “files” in response (what you're already seeing)
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

    payload = {
        "client_ok": True,
        "rpc_probe": rpc_probe,
        "table_probe": table_probe,
        "diagnosis": diagnosis,
        "hints": hints,
        "recommended_sql_files": {
            "rpc.sql": rpc_sql,
            "table_and_trigger.sql": table_sql,
        },
    }
    return _ok(payload, req_id)


def handle_payment_success(
    *,
    account_id: str,
    plan_code: str,
    paid_days: Optional[int] = None,
    provider: str = "paystack",
    provider_ref: Optional[str] = None,
    upgrade_mode: str = "now",
) -> Dict[str, Any]:
    """
    Webhook-facing function (Paystack/etc).

    Permanent strategy:
    - Uses RPC activation by default.
    - Keeps interface stable for webhooks (keyword-only).
    - upgrade_mode accepted (future: 'at_expiry' scheduling).
    """
    req_id = str(uuid.uuid4())

    if not account_id:
        return _fail("missing_account_id", req_id)
    if not plan_code:
        return _fail("missing_plan_code", req_id)

    plan_code_n = (plan_code or "").strip().lower()
    if plan_code_n not in {"monthly", "quarterly", "yearly"}:
        return _fail("invalid_plan_code", req_id, extra={"plan_code": plan_code})

    days_i = int(paid_days) if paid_days is not None else _plan_days(plan_code_n)

    # NOTE: For now, upgrade_mode='at_expiry' is acknowledged but treated as 'now'
    # until you add scheduling logic.
    mode = (upgrade_mode or "now").strip().lower()
    if mode not in {"now", "at_expiry"}:
        mode = "now"

    try:
        activated = activate_subscription_now(account_id=account_id, plan_code=plan_code_n, days=days_i)
        if not activated.get("ok"):
            return _fail(
                "payment_activation_failed",
                req_id,
                root_cause=activated.get("root_cause"),
                extra={
                    "account_id": account_id,
                    "plan_code": plan_code_n,
                    "days": days_i,
                    "provider": provider,
                    "provider_ref": provider_ref,
                    "upgrade_mode": mode,
                },
            )

        return _ok(
            {
                "activated": True,
                "method": activated.get("method"),
                "provider": provider,
                "provider_ref": provider_ref,
                "upgrade_mode": mode,
                "result": activated.get("result") or activated.get("row"),
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
                hint="Unexpected error in payment handler. Check logs by request_id.",
                extra={"account_id": account_id, "plan_code": plan_code, "provider": provider, "provider_ref": provider_ref, "upgrade_mode": mode},
            ),
        )
