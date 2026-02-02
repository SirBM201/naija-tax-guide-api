from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase


# -----------------------------
# Helpers
# -----------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso_z(dt: datetime) -> str:
    # Supabase/Postgrest accepts ISO strings; keep Z for UTC
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
    provider_user_id: Optional[str],
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
    """
    Reads duration_days from public.plans where code = plan_code.
    Returns None if not found.
    """
    db = supabase()
    got = (
        db.table("plans")
        .select("duration_days")
        .eq("code", plan_code)
        .limit(1)
        .execute()
    )
    if got.data:
        val = got.data[0].get("duration_days")
        try:
            return int(val) if val is not None else None
        except Exception:
            return None
    return None


# -----------------------------
# Public API
# -----------------------------
def get_subscription_status(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Dict[str, Any]:
    """
    HISTORY MODEL (Option A):
    - Many rows per account_id
    - Only ONE row can have is_active=true per account_id (enforced by partial unique index)
    - We treat active only if is_active=true AND (expires_at is null OR expires_at > now)
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

    # Get the active row (should be at most 1 due to partial unique index)
    sub = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", aid)
        .eq("is_active", True)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )

    if not sub.data:
        # No active sub; optionally return latest historical record for visibility
        latest = (
            db.table("user_subscriptions")
            .select("*")
            .eq("account_id", aid)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        if not latest.data:
            return {
                "active": False,
                "account_id": aid,
                "plan_code": None,
                "expires_at": None,
                "reason": "no_subscription",
            }

        row = latest.data[0]
        return {
            "active": False,
            "account_id": aid,
            "plan_code": row.get("plan_code"),
            "expires_at": row.get("expires_at"),
            "reason": "no_active_subscription",
        }

    row = sub.data[0]
    expires_at = row.get("expires_at")
    is_active = bool(row.get("is_active"))

    # If expires exists, enforce time check (and auto-deactivate for cleanliness)
    if expires_at:
        dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
        if dt and dt <= _now_utc():
            # Mark inactive in DB (best effort)
            try:
                db.table("user_subscriptions").update(
                    {"is_active": False, "status": "expired", "updated_at": _iso_z(_now_utc())}
                ).eq("id", row["id"]).execute()
            except Exception:
                pass

            return {
                "active": False,
                "account_id": aid,
                "plan_code": row.get("plan_code"),
                "expires_at": expires_at,
                "reason": "expired",
            }

    return {
        "active": is_active,
        "account_id": aid,
        "plan_code": row.get("plan_code"),
        "expires_at": expires_at,
        "reason": "ok",
    }


def manual_activate_subscription(
    account_id: str,
    plan_code: Optional[str],
    expires_at: Optional[str],
) -> Dict[str, Any]:
    """
    HISTORY MODEL activation:
    1) Deactivate any currently-active subscription rows for this account (set is_active=false)
    2) Insert a NEW row with is_active=true
       - expires_at:
         - if provided -> use it
         - else if plan_code exists in plans.duration_days -> now + duration_days
         - else -> now + 30 days
    """
    db = supabase()
    now = _now_utc()

    code = (plan_code or "").strip() or "manual"

    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt is None:
        days = _get_plan_duration_days(code)
        if days is None:
            days = 30
        exp_dt = now + timedelta(days=int(days))

    # 1) Deactivate any currently active row(s) for this account (history preserved)
    # NOTE: Even if two requests race, the partial unique index protects you.
    db.table("user_subscriptions").update(
        {"is_active": False, "updated_at": _iso_z(now)}
    ).eq("account_id", account_id).eq("is_active", True).execute()

    # 2) Insert new active row
    payload = {
        "account_id": account_id,
        "plan_code": code,
        "status": "active",
        "started_at": _iso_z(now),
        "expires_at": _iso_z(exp_dt),
        "is_active": True,
    }

    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]
