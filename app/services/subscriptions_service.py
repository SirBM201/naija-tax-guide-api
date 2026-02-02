from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _to_z(dt: datetime) -> str:
    # Supabase likes ISO8601; "Z" is fine for UTC
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def _find_account_id(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str]
) -> Optional[str]:
    if account_id:
        return account_id

    if not provider or not provider_user_id:
        return None

    db = supabase()
    got = (
        db.table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    if got.data:
        return got.data[0]["id"]
    return None


def _get_plan_duration_days(plan_code: str) -> Optional[int]:
    db = supabase()
    got = (
        db.table("plans")
        .select("duration_days")
        .eq("code", plan_code)
        .limit(1)
        .execute()
    )
    if not got.data:
        return None
    try:
        return int(got.data[0]["duration_days"])
    except Exception:
        return None


def get_subscription_status(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Dict[str, Any]:
    """
    Expected table: user_subscriptions
      - id uuid pk
      - account_id uuid
      - plan_code text
      - status text
      - is_active bool
      - started_at timestamptz
      - expires_at timestamptz
      - created_at timestamptz
      - updated_at timestamptz

    Strategy:
      1) Prefer latest ACTIVE row (is_active=true, expires_at desc)
      2) If none active, return latest row (expires_at desc / created_at desc)
    """
    aid = _find_account_id(account_id, provider, provider_user_id)
    if not aid:
        return {
            "active": False,
            "account_id": None,
            "plan_code": None,
            "expires_at": None,
            "reason": "account_not_found",
        }

    db = supabase()
    now = _now_utc()

    # 1) Try to find an active subscription first
    active_q = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", aid)
        .eq("is_active", True)
        .order("expires_at", desc=True)
        .limit(1)
        .execute()
    )

    row = active_q.data[0] if active_q.data else None

    # 2) If none active, fall back to latest row (history-safe)
    if row is None:
        latest_q = (
            db.table("user_subscriptions")
            .select("*")
            .eq("account_id", aid)
            .order("expires_at", desc=True)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        row = latest_q.data[0] if latest_q.data else None

    if row is None:
        return {
            "active": False,
            "account_id": aid,
            "plan_code": None,
            "expires_at": None,
            "reason": "no_subscription",
        }

    expires_at_raw = row.get("expires_at")
    is_active = bool(row.get("is_active"))
    status = (row.get("status") or "").lower().strip()

    # Enforce expiry time check
    exp_dt = _parse_iso(expires_at_raw) if isinstance(expires_at_raw, str) else None
    if exp_dt and exp_dt <= now:
        is_active = False

    # status can also deactivate it (extra safety)
    if status and status not in ("active", "trialing"):
        is_active = False

    return {
        "active": is_active,
        "account_id": aid,
        "plan_code": row.get("plan_code"),
        "expires_at": expires_at_raw,
        "reason": "ok" if is_active else "inactive_or_expired",
    }


def manual_activate_subscription(
    account_id: str,
    plan_code: Optional[str],
    expires_at: Optional[str],
) -> Dict[str, Any]:
    """
    Manual activation endpoint helper.

    Behavior:
      - If expires_at is provided -> use it
      - Else compute from plans.duration_days for known plan_code
      - Else default to 30 days
      - Writes status/is_active/started_at/updated_at consistently
      - Updates existing row if present (single-row model), else inserts
    """
    db = supabase()
    now = _now_utc()

    code = (plan_code or "manual").strip()

    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt is None:
        days = _get_plan_duration_days(code)
        if not days:
            days = 30
        exp_dt = now + timedelta(days=days)

    payload = {
        "account_id": account_id,
        "plan_code": code,
        "status": "active",
        "is_active": True,
        "started_at": _to_z(now),
        "expires_at": _to_z(exp_dt),
        "updated_at": _to_z(now),
    }

    # Single-row model (recommended): one row per account_id
    got = (
        db.table("user_subscriptions")
        .select("id")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if got.data:
        sub_id = got.data[0]["id"]
        upd = (
            db.table("user_subscriptions")
            .update(payload)
            .eq("id", sub_id)
            .execute()
        )
        return upd.data[0]

    # Insert new
    payload["created_at"] = _to_z(now)
    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]
