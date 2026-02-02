from __future__ import annotations

from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase

# ============================================================
# Time helpers
# ============================================================

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _parse_iso(value: str) -> Optional[datetime]:
    try:
        v = (value or "").replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ============================================================
# Lookups
# ============================================================

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


def _get_plan(plan_code: str) -> Optional[Dict[str, Any]]:
    """
    plans table uses:
      - code (text)  <-- IMPORTANT (not plan_code)
      - name (text)
      - duration_days (int)
    Optional columns you added:
      - price_kobo, currency, grace_days, is_trial, trial_days
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


# ============================================================
# Access computation (active / grace / expired)
# ============================================================

def _compute_access_state(sub_row: Dict[str, Any]) -> Tuple[str, Optional[str], Optional[str]]:
    """
    Returns: (state, expires_at, grace_until)
      - state: "active" | "grace" | "expired"
    """
    expires_at = sub_row.get("expires_at")
    plan_code = (sub_row.get("plan_code") or "").strip()
    is_active_flag = bool(sub_row.get("is_active"))

    # If expiry missing -> fallback to is_active flag
    if not expires_at:
        return ("active" if is_active_flag else "expired", None, None)

    exp_dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
    if not exp_dt:
        return ("active" if is_active_flag else "expired", expires_at, None)

    # grace_days from plans (default 0)
    grace_days = 0
    plan = _get_plan(plan_code) if plan_code else None
    if plan and isinstance(plan.get("grace_days"), int):
        grace_days = int(plan.get("grace_days") or 0)

    now = _now_utc()
    grace_until_dt = exp_dt + timedelta(days=grace_days)

    if is_active_flag and now <= exp_dt:
        return ("active", expires_at, _iso(grace_until_dt))

    if is_active_flag and now <= grace_until_dt:
        return ("grace", expires_at, _iso(grace_until_dt))

    return ("expired", expires_at, _iso(grace_until_dt))


# ============================================================
# Public API (used by routes + ask)
# ============================================================

def get_subscription_status(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Dict[str, Any]:
    """
    Option A (history + single active row):
      - Keep many rows in user_subscriptions as history
      - Enforce only ONE active row via partial unique index

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


# ============================================================
# Core mutations
# ============================================================

def _deactivate_any_active(account_id: str, reason: str = "replaced") -> None:
    """
    Turn off existing active row (history preserved).
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
    """
    Uses plans.duration_days if available; fallback 30 days.
    """
    plan = _get_plan(plan_code)
    duration_days = 30
    if plan and isinstance(plan.get("duration_days"), int):
        duration_days = int(plan.get("duration_days") or 30)
    return starts_at + timedelta(days=duration_days)


def activate_subscription_now(
    account_id: str,
    plan_code: str,
    *,
    status: str = "active",
) -> Dict[str, Any]:
    """
    Creates a NEW subscription row and deactivates any previous active row.
    Supports upgrade/downgrade history cleanly.
    """
    starts = _now_utc()
    expires = _build_expiry_from_plan(plan_code, starts)

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


# ============================================================
# Upgrade / Downgrade scheduling (period-end change)
# ============================================================

def schedule_plan_change_at_expiry(account_id: str, next_plan_code: str) -> Dict[str, Any]:
    """
    Stores pending_plan_code + pending_starts_at on the current active row.
    Your table screenshot shows these columns exist now.
    """
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return activate_subscription_now(account_id, next_plan_code, status="active")

    exp_dt = _parse_iso(cur.get("expires_at") or "")
    if not exp_dt:
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
    Call this cheaply in /api/ask (optional) or later via cron.
    If pending is due, create a new row for the next plan.
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
    if not starts_dt or _now_utc() < starts_dt:
        return None

    # clear pending on old row
    db.table("user_subscriptions").update(
        {
            "pending_plan_code": None,
            "pending_starts_at": None,
            "updated_at": _iso(_now_utc()),
        }
    ).eq("id", cur["id"]).execute()

    return activate_subscription_now(account_id, pending_plan, status="active")


# ============================================================
# Trial
# ============================================================

def start_trial_if_eligible(account_id: str, trial_plan_code: str = "trial") -> Dict[str, Any]:
    """
    Requires accounts.has_used_trial boolean column.
    """
    db = supabase()
    acc = (
        db.table("accounts")
        .select("id, has_used_trial")
        .eq("id", account_id)
        .limit(1)
        .execute()
    )
    if not acc.data:
        return {"ok": False, "error": "account_not_found"}

    used = bool(acc.data[0].get("has_used_trial"))
    if used:
        return {"ok": False, "error": "trial_already_used"}

    sub = activate_subscription_now(account_id, trial_plan_code, status="trial")
    db.table("accounts").update({"has_used_trial": True}).eq("id", account_id).execute()

    return {"ok": True, "subscription": sub}


# ============================================================
# REQUIRED by /routes/subscriptions.py  (Fixes your boot crash)
# ============================================================

def manual_activate_subscription(account_id: str, plan_code: Optional[str], expires_at: Optional[str]) -> Dict[str, Any]:
    """
    Backward-compatible manual activation for /subscription/activate route.

    Behavior:
      - keeps history (inserts NEW row)
      - ensures only one active subscription by deactivating previous active row
      - if expires_at missing, uses plans.duration_days fallback
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


# ============================================================
# Webhook-ready: payment success handler (Fixes your boot crash)
# ============================================================

def _safe_get(d: Any, path: str, default=None):
    """
    Safe nested getter: _safe_get(obj, "data.metadata.account_id")
    """
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _record_paystack_event_if_new(event_id: str, payload: Dict[str, Any]) -> bool:
    """
    Idempotency: returns True if inserted (new), False if already exists.
    Requires a table paystack_events with unique(event_id) OR similar.
    If you use a different table name, change it here.
    """
    if not event_id:
        return True  # can't dedupe

    db = supabase()

    # Check exists
    exists = (
        db.table("paystack_events")
        .select("id")
        .eq("event_id", event_id)
        .limit(1)
        .execute()
    )
    if exists.data:
        return False

    # Insert
    db.table("paystack_events").insert(
        {
            "event_id": event_id,
            "payload": payload,
            "created_at": _iso(_now_utc()),
        }
    ).execute()
    return True


def _insert_payment_row(
    *,
    account_id: str,
    provider: str,
    provider_ref: Optional[str],
    amount_kobo: Optional[int],
    currency: Optional[str],
    status: str,
    plan_code: Optional[str],
    raw: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Writes a record to payments table if you have it.
    If your payments table columns differ, adjust this payload to match.
    """
    db = supabase()
    now = _iso(_now_utc())

    payload: Dict[str, Any] = {
        "account_id": account_id,
        "provider": provider,
        "provider_ref": provider_ref,
        "amount_kobo": amount_kobo,
        "currency": currency or "NGN",
        "status": status,
        "plan_code": plan_code,
        "created_at": now,
        "updated_at": now,
    }
    if raw is not None:
        payload["raw"] = raw

    db.table("payments").insert(payload).execute()


def handle_payment_success(provider: str, event_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    REQUIRED by app/routes/webhooks.py

    Expected (Paystack style):
      event_payload["event"] == "charge.success"
      event_payload["data"]["reference"] = provider_ref
      event_payload["data"]["amount"] = kobo
      event_payload["data"]["currency"] = "NGN"
      event_payload["data"]["metadata"]["account_id"] = "<uuid>"
      event_payload["data"]["metadata"]["plan_code"] = "monthly|quarterly|yearly|..."

    What it does:
      1) idempotency check via paystack_events (event_id)
      2) records payment (optional but recommended)
      3) activates subscription (Option A history)
    """
    provider = (provider or "").strip().lower() or "unknown"

    event_id = (
        event_payload.get("id")
        or event_payload.get("event_id")
        or _safe_get(event_payload, "data.id")
        or _safe_get(event_payload, "data.reference")
    )

    # Idempotency (if table exists)
    try:
        is_new = _record_paystack_event_if_new(str(event_id), event_payload)
        if not is_new:
            return {"ok": True, "status": "duplicate_ignored"}
    except Exception:
        # If table doesn't exist yet, don't crash webhook
        pass

    account_id = _safe_get(event_payload, "data.metadata.account_id")
    plan_code = _safe_get(event_payload, "data.metadata.plan_code") or _safe_get(event_payload, "data.metadata.plan")  # tolerate
    provider_ref = _safe_get(event_payload, "data.reference") or str(event_id)
    amount_kobo = _safe_get(event_payload, "data.amount")
    currency = _safe_get(event_payload, "data.currency") or "NGN"

    if not account_id or not plan_code:
        return {
            "ok": False,
            "error": "missing_metadata",
            "need": ["data.metadata.account_id", "data.metadata.plan_code"],
        }

    # Save payment row (optional)
    try:
        _insert_payment_row(
            account_id=account_id,
            provider=provider,
            provider_ref=provider_ref,
            amount_kobo=int(amount_kobo) if amount_kobo is not None else None,
            currency=currency,
            status="success",
            plan_code=str(plan_code),
            raw=event_payload,
        )
    except Exception:
        # don't block activation if payment logging fails
        pass

    # Activate subscription now
    sub = activate_subscription_now(account_id, str(plan_code), status="active")
    return {"ok": True, "status": "activated", "subscription": sub}
