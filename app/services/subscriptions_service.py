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
    # Supabase likes ISO; keep Z
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# -----------------------------
# Lookups
# -----------------------------
def _find_account_id(account_id: Optional[str], provider: Optional[str], provider_user_id: Optional[str]) -> Optional[str]:
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


def _get_plan(plan_code: str) -> Optional[Dict[str, Any]]:
    """
    plans table (based on your screenshot):
      - code (text)   <-- IMPORTANT: it's code, NOT plan_code
      - name (text)
      - duration_days (int)
      - created_at (timestamptz)

    We will ADD (via SQL) these optional columns:
      - price_kobo (bigint)
      - currency (text)
      - grace_days (int)
      - is_trial (bool)
      - trial_days (int)
    """
    if not plan_code:
        return None

    db = supabase()
    res = (
        db.table("plans")
        .select("*")
        .eq("code", plan_code)
        .limit(1)
        .execute()
    )
    if res.data:
        return res.data[0]
    return None


def _get_latest_sub_row(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Option A: keep history.
    Latest row is the truth for display, but active access is computed via dates + grace.
    """
    db = supabase()
    res = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    if res.data:
        return res.data[0]
    return None


def _get_active_sub_row(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch the single active row (enforced by partial unique index).
    """
    db = supabase()
    res = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", account_id)
        .eq("is_active", True)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    if res.data:
        return res.data[0]
    return None


# -----------------------------
# Access computation (active / grace / expired)
# -----------------------------
def _compute_access_state(sub_row: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Returns: (state, expires_at, grace_until)
      - state: "active" | "grace" | "expired"
    """
    expires_at = sub_row.get("expires_at")
    plan_code = sub_row.get("plan_code") or ""
    is_active_flag = bool(sub_row.get("is_active"))

    # If there is no expiry, treat is_active flag as truthy (manual/legacy),
    # but still "active" only if is_active_flag is True.
    if not expires_at:
        return ("active" if is_active_flag else "expired", None, None)

    exp_dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
    if not exp_dt:
        # can't parse: fall back to flag
        return ("active" if is_active_flag else "expired", expires_at, None)

    # Grace days come from the plan row (default 0)
    plan = _get_plan(plan_code) if plan_code else None
    grace_days = 0
    if plan and isinstance(plan.get("grace_days"), int):
        grace_days = int(plan.get("grace_days") or 0)

    now = _now_utc()
    grace_until_dt = exp_dt + timedelta(days=grace_days)

    if now <= exp_dt and is_active_flag:
        return ("active", expires_at, _iso(grace_until_dt))
    if now <= grace_until_dt and is_active_flag:
        return ("grace", expires_at, _iso(grace_until_dt))
    return ("expired", expires_at, _iso(grace_until_dt))


# -----------------------------
# Public API
# -----------------------------
def get_subscription_status(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Dict[str, Any]:
    """
    Option A (history):
      - Keep many rows per account_id (history)
      - Enforce only one active row per account_id (partial unique index)

    Returns:
      active: bool  (true in ACTIVE or GRACE)
      state: "none" | "active" | "grace" | "expired"
      plan_code, expires_at, grace_until
    """
    aid = _find_account_id(account_id, provider, provider_user_id)
    if not aid:
        return {
            "active": False,
            "state": "none",
            "account_id": None,
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
            "reason": "account_not_found",
        }

    latest = _get_latest_sub_row(aid)
    if not latest:
        return {
            "active": False,
            "state": "none",
            "account_id": aid,
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
            "reason": "no_subscription",
        }

    state, expires_at, grace_until = _compute_access_state(latest)
    active = state in ("active", "grace")

    return {
        "active": active,
        "state": state,
        "account_id": aid,
        "plan_code": latest.get("plan_code"),
        "expires_at": expires_at,
        "grace_until": grace_until,
        "reason": "ok" if active else "inactive_or_expired",
    }


# -----------------------------
# Core mutations
# -----------------------------
def _deactivate_any_active(account_id: str, reason: str = "replaced") -> None:
    """
    Turn off existing active row (if any). Keep it as history.
    """
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return

    db.table("user_subscriptions").update(
        {
            "is_active": False,
            "status": reason,
            "updated_at": _iso(_now_utc()),
        }
    ).eq("id", cur["id"]).execute()


def _build_expiry_from_plan(plan_code: str, starts_at: datetime) -> datetime:
    plan = _get_plan(plan_code)
    # default 30 days if plan not found
    duration_days = 30
    if plan and isinstance(plan.get("duration_days"), int):
        duration_days = int(plan.get("duration_days") or 30)
    return starts_at + timedelta(days=duration_days)


def activate_subscription_now(
    account_id: str,
    plan_code: str,
    *,
    status: str = "active",
    is_trial: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Creates a NEW subscription row starting now and deactivates any previous active row.
    This is the cleanest way to support upgrade/downgrade + history.
    """
    starts = _now_utc()
    expires = _build_expiry_from_plan(plan_code, starts)

    # if plans says it's a trial, reflect it
    plan = _get_plan(plan_code)
    if is_trial is None:
        is_trial = bool(plan.get("is_trial")) if plan else False

    _deactivate_any_active(account_id, reason="replaced")

    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": status,
        "started_at": _iso(starts),
        "expires_at": _iso(expires),
        "is_active": True,
        "updated_at": _iso(starts),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]


def schedule_plan_change_at_expiry(account_id: str, next_plan_code: str) -> Dict[str, Any]:
    """
    Upgrade/downgrade (at period end):
    Store pending change on the CURRENT active row.
    Requires SQL columns: pending_plan_code, pending_starts_at (we provide SQL below).
    """
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        # no active -> activate now
        return activate_subscription_now(account_id, next_plan_code, status="active")

    expires_at = cur.get("expires_at")
    exp_dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
    if not exp_dt:
        # if expiry missing, do immediate change
        return activate_subscription_now(account_id, next_plan_code, status="active")

    upd = (
        db.table("user_subscriptions")
        .update(
            {
                "pending_plan_code": next_plan_code,
                "pending_starts_at": _iso(exp_dt),
                "updated_at": _iso(_now_utc()),
            }
        )
        .eq("id", cur["id"])
        .execute()
    )
    return upd.data[0]


def apply_scheduled_change_if_due(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Call this from your /api/ask pipeline (cheap check) or a cron later.
    If pending is due, create the next plan row and deactivate old.
    """
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return None

    pending_plan = (cur.get("pending_plan_code") or "").strip()
    pending_starts_at = cur.get("pending_starts_at")

    if not pending_plan or not pending_starts_at:
        return None

    starts_dt = _parse_iso(pending_starts_at) if isinstance(pending_starts_at, str) else None
    if not starts_dt:
        return None

    if _now_utc() < starts_dt:
        return None

    # clear pending on old row
    db.table("user_subscriptions").update(
        {
            "pending_plan_code": None,
            "pending_starts_at": None,
            "updated_at": _iso(_now_utc()),
        }
    ).eq("id", cur["id"]).execute()

    # activate new plan now
    return activate_subscription_now(account_id, pending_plan, status="active")


# -----------------------------
# Trial
# -----------------------------
def start_trial_if_eligible(account_id: str, trial_plan_code: str = "trial") -> Dict[str, Any]:
    """
    Very simple trial rule (MVP):
      - Add accounts.has_used_trial boolean (SQL below)
      - If already used -> return error
      - Else activate trial and set has_used_trial = true
    """
    db = supabase()
    acc = db.table("accounts").select("id, has_used_trial").eq("id", account_id).limit(1).execute()
    if not acc.data:
        return {"ok": False, "error": "account_not_found"}

    used = bool(acc.data[0].get("has_used_trial"))
    if used:
        return {"ok": False, "error": "trial_already_used"}

    # Activate trial now
    sub = activate_subscription_now(account_id, trial_plan_code, status="trial")

    # mark used
    db.table("accounts").update({"has_used_trial": True}).eq("id", account_id).execute()
    return {"ok": True, "subscription": sub}


# -----------------------------
# Backward-compatible manual activation (your route uses this)
# -----------------------------
def manual_activate_subscription(account_id: str, plan_code: Optional[str], expires_at: Optional[str]) -> Dict[str, Any]:
    """
    Backward-compatible manual activation for /subscription/activate route.
    Creates a NEW subscription row and deactivates any previous active row (history preserved).
    """
    plan = (plan_code or "manual").strip() or "manual"
    starts = _now_utc()

    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt is None:
        exp_dt = _build_expiry_from_plan(plan, starts)

    _deactivate_any_active(account_id, reason="replaced")

    payload = {
        "account_id": account_id,
        "plan_code": plan,
        "status": "active",
        "started_at": _iso(starts),
        "expires_at": _iso(exp_dt),
        "is_active": True,
        "updated_at": _iso(starts),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]

from typing import Optional, Dict, Any
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase

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

def _build_expiry_from_plan(plan_code: str, started_at: datetime) -> datetime:
    # simple mapping for now (edit later to use plans table)
    p = (plan_code or "").lower()
    if p == "yearly":
        return started_at + timedelta(days=365)
    if p == "quarterly":
        return started_at + timedelta(days=90)
    # default monthly/manual
    return started_at + timedelta(days=30)

def _deactivate_any_active(account_id: str, reason: str = "replaced") -> None:
    db = supabase()
    now = _iso(_now_utc())
    # deactivate any currently active rows (history preserved)
    db.table("user_subscriptions") \
      .update({"is_active": False, "status": reason, "updated_at": now}) \
      .eq("account_id", account_id) \
      .eq("is_active", True) \
      .execute()

def manual_activate_subscription(account_id: str, plan_code: Optional[str], expires_at: Optional[str]) -> Dict[str, Any]:
    """
    Route-compatible function required by app/routes/subscriptions.py

    Behavior:
    - keeps history (inserts a NEW row)
    - ensures only one active subscription by deactivating previous active rows
    """
    plan = (plan_code or "manual").strip() or "manual"
    started = _now_utc()

    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt is None:
        exp_dt = _build_expiry_from_plan(plan, started)

    _deactivate_any_active(account_id, reason="replaced")

    payload = {
        "account_id": account_id,
        "plan_code": plan,
        "status": "active",
        "started_at": _iso(started),
        "expires_at": _iso(exp_dt),
        "is_active": True,
        "created_at": _iso(started),
        "updated_at": _iso(started),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]
