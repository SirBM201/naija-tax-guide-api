# app/routes/_debug.py
from __future__ import annotations

from typing import Any, Dict

from flask import Blueprint, jsonify, request

from app.core.supabase_client import supabase

bp = Blueprint("_debug", __name__)


def _admin_ok(req) -> bool:
    expected = (request.environ.get("ADMIN_KEY") or "")  # usually not set here
    expected = expected or ""  # keep safe
    expected = (expected or "").strip()

    # Prefer env var ADMIN_KEY
    import os
    expected = (os.getenv("ADMIN_KEY") or "").strip()

    got = (req.headers.get("X-Admin-Key") or "").strip()
    return bool(expected) and got == expected


@bp.get("/_debug/ping")
def ping():
    if not _admin_ok(request):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    return jsonify({"ok": True, "ping": "pong"}), 200


@bp.get("/_debug/subscription_health")
def subscription_health():
    if not _admin_ok(request):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    # Probe RPC + table read without crashing the app
    rpc_ok = False
    rpc_data = None
    table_ok = False
    sample_count = 0
    sample_keys = []

    try:
        # Call with a dummy UUID; function should still be callable even if returns null
        res = supabase.rpc("bms_read_subscription", {"p_account_id": "00000000-0000-0000-0000-000000000000"}).execute()
        rpc_ok = True
        rpc_data = getattr(res, "data", None)
    except Exception:
        rpc_ok = False

    try:
        res = supabase.table("user_subscriptions").select("*").limit(1).execute()
        rows = (res.data or []) if hasattr(res, "data") else []
        table_ok = True
        sample_count = len(rows)
        if rows and isinstance(rows[0], dict):
            sample_keys = list(rows[0].keys())
    except Exception:
        table_ok = False

    recommended_sql_files: Dict[str, str] = {
        "rpc.sql": """-- RPC READ (stable)
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
""",
        "table_and_trigger.sql": """-- Ensure table exists with the exact columns our API expects
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
""",
    }

    diagnosis = []
    if rpc_ok:
        diagnosis.append("RPC bms_read_subscription is callable (good).")
    else:
        diagnosis.append("RPC bms_read_subscription NOT callable (fix by running rpc.sql).")

    if table_ok:
        diagnosis.append("Table user_subscriptions is readable via PostgREST (good).")
    else:
        diagnosis.append("Table user_subscriptions NOT readable (check RLS / schema).")

    diagnosis.append("Permanent fix: use RPC bms_activate_subscription for activation; keep table schema stable.")

    return jsonify(
        {
            "ok": True,
            "client_ok": True,
            "rpc_probe": {"ok": rpc_ok, "data": rpc_data},
            "table_probe": {"ok": table_ok, "sample_count": sample_count, "sample_keys": sample_keys},
            "diagnosis": diagnosis,
            "hints": {},
            "recommended_sql_files": recommended_sql_files,
        }
    ), 200
