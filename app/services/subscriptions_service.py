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


def _get_plan(code: str) -> Optional[Dict[str, Any]]:
    code = (code or "").strip()
    if not code:
        return None
    db = supabase()
    res = db.table("plans").select("*").eq("code", code).limit(1).execute()
    return res.data[0] if res.data else None


def _get_latest_sub_row(account_id: str) -> Optional[Dict[str, Any]]:
    db = supabase()
    res = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", account_id)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def _get_active_sub_row(account_id: str) -> Optional[Dict[str, Any]]:
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
    return res.data[0] if res.data else None


# -----------------------------
# Access computation (active / grace / expired)
# -----------------------------
def _compute_access_state(sub_row: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Returns: (state, expires_at, grace_until)
      - state: "active" | "grace" | "expired"
    """
    expires_at = sub_row.get("expires_at")
    plan_code = (sub_row.get("plan_code") or "").strip()
    is_active_flag = bool(sub_row.get("is_active"))

    if not expires_at:
        # No expiry means we trust is_active flag
        return ("active" if is_active_flag else "expired", None, None)

    exp_dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
    if not exp_dt:
        # Can't parse -> trust flag, but still return raw expires_at
        return ("active" if is_active_flag else "expired", expires_at, None)

    plan = _get_plan(plan_code) if plan_code else None
    grace_days = 0
    if plan and plan.get("grace_days") is not None:
        try:
            grace_days = int(plan.get("grace_days") or 0)
        except Exception:
            grace_days = 0

    now = _now_utc()
    grace_until_dt = exp_dt + timedelta(days=grace_days)

    if is_active_flag and now <= exp_dt:
        return ("active", expires_at, _iso(grace_until_dt))
    if is_active_flag and now <= grace_until_dt:
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

    # Your user_subscriptions columns list doesn't show status/updated_at,
    # so we update only what we KNOW exists. (is_active definitely exists)
    try:
        db.table("user_subscriptions").update({"is_active": False}).eq("id", cur["id"]).execute()
    except Exception:
        # fallback: try update more fields if they exist in some environments
        try:
            db.table("user_subscriptions").update(
                {"is_active": False, "status": reason, "updated_at": _iso(_now_utc())}
            ).eq("id", cur["id"]).execute()
        except Exception:
            pass


def _build_expiry_from_plan(plan_code: str, starts_at: datetime) -> datetime:
    """
    Uses plans.duration_days by default.
    If plan.is_trial == true and trial_days exists, use trial_days.
    """
    plan = _get_plan(plan_code)
    duration_days = 30

    if plan:
        try:
            duration_days = int(plan.get("duration_days") or 30)
        except Exception:
            duration_days = 30

        # trial override
        try:
            if bool(plan.get("is_trial")) and plan.get("trial_days") is not None:
                duration_days = int(plan.get("trial_days") or duration_days)
        except Exception:
            pass

    return starts_at + timedelta(days=duration_days)


def activate_subscription_now(account_id: str, plan_code: str, *, status: str = "active") -> Dict[str, Any]:
    """
    Creates a NEW subscription row starting now and deactivates any previous active row.
    """
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip()
    if not account_id or not plan_code:
        raise ValueError("account_id and plan_code are required")

    starts = _now_utc()
    expires = _build_expiry_from_plan(plan_code, starts)

    _deactivate_any_active(account_id, reason="replaced")

    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "started_at": _iso(starts),
        "expires_at": _iso(expires),
        "is_active": True,
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]


def schedule_plan_change_at_expiry(account_id: str, next_plan_code: str) -> Dict[str, Any]:
    """
    Store pending change on CURRENT active row:
      - pending_plan_code
      - pending_starts_at (usually expires_at)
    """
    account_id = (account_id or "").strip()
    next_plan_code = (next_plan_code or "").strip()
    if not account_id or not next_plan_code:
        raise ValueError("account_id and next_plan_code are required")

    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return activate_subscription_now(account_id, next_plan_code, status="active")

    expires_at = cur.get("expires_at")
    exp_dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
    if not exp_dt:
        return activate_subscription_now(account_id, next_plan_code, status="active")

    upd = (
        db.table("user_subscriptions")
        .update(
            {
                "pending_plan_code": next_plan_code,
                "pending_starts_at": _iso(exp_dt),
            }
        )
        .eq("id", cur["id"])
        .execute()
    )
    return upd.data[0]


def apply_scheduled_change_if_due(account_id: str) -> Optional[Dict[str, Any]]:
    """
    If pending is due, create next plan row and deactivate old.
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return None

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
    try:
        db.table("user_subscriptions").update(
            {"pending_plan_code": None, "pending_starts_at": None}
        ).eq("id", cur["id"]).execute()
    except Exception:
        pass

    return activate_subscription_now(account_id, pending_plan, status="active")


# -----------------------------
# Trial
# -----------------------------
def start_trial_if_eligible(account_id: str, trial_plan_code: str = "trial") -> Dict[str, Any]:
    """
    Simple MVP eligibility: trial only once per account (no schema change required).
    Rule:
      - if user_subscriptions ever had plan_code == trial_plan_code -> block
      - else activate trial now
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "account_id_required"}

    db = supabase()
    seen = (
        db.table("user_subscriptions")
        .select("id")
        .eq("account_id", account_id)
        .eq("plan_code", trial_plan_code)
        .limit(1)
        .execute()
    )
    if seen.data:
        return {"ok": False, "error": "trial_already_used"}

    sub = activate_subscription_now(account_id, trial_plan_code, status="trial")
    return {"ok": True, "subscription": sub}


# -----------------------------
# Manual activation (required by routes)
# -----------------------------
def manual_activate_subscription(account_id: str, plan_code: Optional[str], expires_at: Optional[str]) -> Dict[str, Any]:
    """
    Backward-compatible manual activation for /subscription/activate route.
    - Inserts a NEW row (history kept)
    - Deactivates old active row
    - If expires_at missing, compute from plan duration_days
    """
    account_id = (account_id or "").strip()
    plan = (plan_code or "manual").strip() or "manual"
    if not account_id:
        raise ValueError("account_id is required")

    starts = _now_utc()
    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt is None:
        exp_dt = _build_expiry_from_plan(plan, starts)

    _deactivate_any_active(account_id, reason="replaced")

    payload = {
        "account_id": account_id,
        "plan_code": plan,
        "started_at": _iso(starts),
        "expires_at": _iso(exp_dt),
        "is_active": True,
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    return ins.data[0]


# -----------------------------
# Webhook-ready: payment success handler
# -----------------------------
def handle_payment_success(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Idempotent-ish payment handler:
    - store event in paystack_events (best effort)
    - store payment row (best effort)
    - activate subscription (or schedule if upgrade_mode='at_expiry')
    """
    db = supabase()

    event_id = (payload.get("event_id") or "").strip() or None
    provider = (payload.get("provider") or "paystack").strip()
    reference = payload.get("reference")
    account_id = (payload.get("account_id") or "").strip()
    plan_code = (payload.get("plan_code") or "").strip()
    amount_kobo = payload.get("amount_kobo")
    currency = (payload.get("currency") or "NGN").strip()
    raw = payload.get("raw")
    upgrade_mode = (payload.get("upgrade_mode") or "now").strip().lower()  # now | at_expiry

    if not account_id or not plan_code:
        return {"ok": False, "error": "missing_account_id_or_plan_code"}

    # 1) store event (best effort)
    if event_id:
        try:
            db.table("paystack_events").insert({"event_id": event_id, "payload": raw}).execute()
        except Exception:
            pass

    # 2) store payment (best effort) - columns may differ; do not crash webhook
    try:
        db.table("payments").insert(
            {
                "account_id": account_id,
                "provider": provider,
                "reference": reference,
                "amount_kobo": amount_kobo,
                "currency": currency,
                "status": "success",
                "plan_code": plan_code,
                "raw": raw,
            }
        ).execute()
    except Exception:
        pass

    # 3) apply subscription
    if upgrade_mode == "at_expiry":
        row = schedule_plan_change_at_expiry(account_id, plan_code)
        return {"ok": True, "mode": "scheduled", "subscription": row}

    row = activate_subscription_now(account_id, plan_code, status="active")
    return {"ok": True, "mode": "activated", "subscription": row}
