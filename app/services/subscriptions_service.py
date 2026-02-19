# app/services/subscriptions_service.py
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase


# -----------------------------
# Time helpers
# -----------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: str) -> Optional[datetime]:
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# -----------------------------
# Lookups
# -----------------------------
def _find_account_id(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Optional[str]:
    """
    If account_id is given -> use it.
    Else try to find account by (provider, provider_user_id) from accounts table.
    """
    if account_id:
        return account_id.strip() or None

    if not provider or not provider_user_id:
        return None

    rows = (
        supabase.table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
        .data
        or []
    )
    return rows[0]["id"] if rows else None


def _get_active_plan(plan_code: str) -> Optional[Dict[str, Any]]:
    if not plan_code:
        return None
    rows = (
        supabase.table("plans")
        .select("plan_code,name,price_ngn,duration_days,active")
        .eq("plan_code", plan_code)
        .eq("active", True)
        .limit(1)
        .execute()
        .data
        or []
    )
    return rows[0] if rows else None


def get_subscription_status(
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Returns a normalized view of subscription state.
    """
    aid = _find_account_id(account_id, provider, provider_user_id)
    if not aid:
        return {
            "account_id": None,
            "active": False,
            "expires_at": None,
            "grace_until": None,
            "plan_code": None,
            "reason": "no_account",
            "state": "none",
        }

    rows = (
        supabase.table("user_subscriptions")
        .select("account_id,plan_code,active,expires_at,grace_until")
        .eq("account_id", aid)
        .limit(1)
        .execute()
        .data
        or []
    )

    if not rows:
        return {
            "account_id": aid,
            "active": False,
            "expires_at": None,
            "grace_until": None,
            "plan_code": None,
            "reason": "no_subscription",
            "state": "none",
        }

    sub = rows[0]
    active = bool(sub.get("active"))
    expires_at = sub.get("expires_at")
    grace_until = sub.get("grace_until")
    plan_code = sub.get("plan_code")

    now = _now_utc()
    exp_dt = _parse_iso(expires_at) if expires_at else None
    grace_dt = _parse_iso(grace_until) if grace_until else None

    if active and exp_dt and exp_dt > now:
        return {
            "account_id": aid,
            "active": True,
            "expires_at": expires_at,
            "grace_until": grace_until,
            "plan_code": plan_code,
            "reason": "active",
            "state": "active",
        }

    # expired but still inside grace window
    if (not active or (exp_dt and exp_dt <= now)) and grace_dt and grace_dt > now:
        return {
            "account_id": aid,
            "active": True,
            "expires_at": expires_at,
            "grace_until": grace_until,
            "plan_code": plan_code,
            "reason": "grace",
            "state": "grace",
        }

    return {
        "account_id": aid,
        "active": False,
        "expires_at": expires_at,
        "grace_until": grace_until,
        "plan_code": plan_code,
        "reason": "expired",
        "state": "expired",
    }


# -----------------------------
# Trial / Manual activation
# -----------------------------
def start_trial_if_eligible(
    account_id: str,
    plan_code: str = "trial",
    duration_days: int = 7,
) -> Dict[str, Any]:
    """
    Create/update a subscription row for a trial if:
    - user_subscriptions row doesn't exist OR is inactive/expired.
    """
    if not account_id:
        return {"ok": False, "error": "missing_account_id"}

    now = _now_utc()
    expires = now + timedelta(days=duration_days)

    # if subscription exists and active, do nothing
    current = (
        supabase.table("user_subscriptions")
        .select("active,expires_at,grace_until,plan_code")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
        .data
        or []
    )

    if current:
        sub = current[0]
        if sub.get("active") and (_parse_iso(sub.get("expires_at") or "") or now) > now:
            return {"ok": True, "status": "already_active"}

        # update to trial
        supabase.table("user_subscriptions").update(
            {
                "plan_code": plan_code,
                "active": True,
                "expires_at": _iso(expires),
                "grace_until": _iso(expires + timedelta(days=3)),
                "updated_at": _iso(now),
            }
        ).eq("account_id", account_id).execute()
        return {"ok": True, "status": "trial_updated"}

    # create trial
    supabase.table("user_subscriptions").insert(
        {
            "account_id": account_id,
            "plan_code": plan_code,
            "active": True,
            "expires_at": _iso(expires),
            "grace_until": _iso(expires + timedelta(days=3)),
            "created_at": _iso(now),
            "updated_at": _iso(now),
        }
    ).execute()

    return {"ok": True, "status": "trial_created"}


def manual_activate_subscription(
    account_id: str,
    plan_code: str,
) -> Dict[str, Any]:
    """
    Admin/manual activation. Sets active = True and expires_at based on plan duration.
    """
    if not account_id:
        return {"ok": False, "error": "missing_account_id"}
    plan = _get_active_plan(plan_code)
    if not plan:
        return {"ok": False, "error": "invalid_plan"}

    now = _now_utc()
    expires = now + timedelta(days=int(plan.get("duration_days") or 30))

    # upsert subscription row
    existing = (
        supabase.table("user_subscriptions")
        .select("account_id")
        .eq("account_id", account_id)
        .limit(1)
        .execute()
        .data
        or []
    )

    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "active": True,
        "expires_at": _iso(expires),
        "grace_until": _iso(expires + timedelta(days=3)),
        "updated_at": _iso(now),
    }

    if existing:
        supabase.table("user_subscriptions").update(payload).eq("account_id", account_id).execute()
    else:
        payload["created_at"] = _iso(now)
        supabase.table("user_subscriptions").insert(payload).execute()

    return {"ok": True, "expires_at": _iso(expires), "plan_code": plan_code}


# -----------------------------
# Paystack webhook handler hook
# -----------------------------
def handle_payment_success(reference: str) -> Dict[str, Any]:
    """
    Called from routes/webhooks.py.
    Looks up the payment row, then activates subscription accordingly.
    Your DB tables may differ — adjust selection keys if needed.
    """
    ref = (reference or "").strip()
    if not ref:
        return {"ok": False, "error": "missing_reference"}

    rows = (
        supabase.table("payments")
        .select("id,account_id,plan_code,status,reference")
        .eq("reference", ref)
        .limit(1)
        .execute()
        .data
        or []
    )
    if not rows:
        return {"ok": False, "error": "payment_not_found"}

    pay = rows[0]
    if (pay.get("status") or "").lower() not in ("success", "successful", "paid"):
        # still allow activation if your system marks success differently
        # but keep conservative by default:
        return {"ok": False, "error": "payment_not_success"}

    account_id = pay.get("account_id")
    plan_code = pay.get("plan_code")

    if not account_id or not plan_code:
        return {"ok": False, "error": "payment_missing_fields"}

    act = manual_activate_subscription(account_id=account_id, plan_code=plan_code)
    if not act.get("ok"):
        return {"ok": False, "error": "activation_failed", "detail": act}

    # mark payment consumed/processed (optional)
    try:
        supabase.table("payments").update({"processed": True}).eq("id", pay["id"]).execute()
    except Exception:
        pass

    return {"ok": True, "activated": act}
