from typing import Optional, Dict, Any, Tuple
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

def _iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

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
    db = supabase()
    res = db.table("plans").select("*").eq("code", plan_code).limit(1).execute()
    return res.data[0] if res.data else None

def _log_event(
    account_id: str,
    event_type: str,
    from_plan: Optional[str] = None,
    to_plan: Optional[str] = None,
    provider: Optional[str] = None,
    reference: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        db = supabase()
        db.table("subscription_events").insert({
            "account_id": account_id,
            "event_type": event_type,
            "from_plan": from_plan,
            "to_plan": to_plan,
            "provider": provider,
            "reference": reference,
            "payload": payload or {},
        }).execute()
    except Exception:
        # Never break core flow due to logging
        pass

def _deactivate_current_active(account_id: str, reason_status: str = "inactive") -> Optional[Dict[str, Any]]:
    db = supabase()
    cur = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", account_id)
        .eq("is_active", True)
        .limit(1)
        .execute()
    )
    if not cur.data:
        return None

    row = cur.data[0]
    db.table("user_subscriptions").update({
        "is_active": False,
        "status": reason_status,
        "updated_at": _iso_z(_now_utc()),
    }).eq("id", row["id"]).execute()
    return row

def _compute_expiry(plan_code: str, now: Optional[datetime] = None) -> Tuple[datetime, int]:
    """
    Returns (expires_at, grace_days)
    """
    now = now or _now_utc()
    plan = _get_plan(plan_code)
    # Fallbacks if plan table not configured fully
    duration_days = int(plan.get("duration_days", 30)) if plan else 30
    grace_days = int(plan.get("grace_days", 0)) if plan else 0

    expires_at = now + timedelta(days=duration_days)
    return expires_at, grace_days

def _is_within_access_window(expires_at_iso: Optional[str], grace_days: int) -> bool:
    """
    Access is valid if now <= expires_at + grace_days
    """
    if not expires_at_iso:
        return False
    dt = _parse_iso(expires_at_iso) if isinstance(expires_at_iso, str) else None
    if not dt:
        return False
    return _now_utc() <= (dt + timedelta(days=grace_days))

def get_subscription_status(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Dict[str, Any]:
    """
    Uses user_subscriptions latest active row (preferred),
    falls back to latest row by created_at if none active.

    Enforces:
      - expires_at (hard expiry)
      - grace_days (soft access window)
    """
    aid = _find_account_id(account_id, provider, provider_user_id)
    if not aid:
        return {
            "active": False,
            "account_id": None,
            "plan_code": None,
            "expires_at": None,
            "in_grace": False,
            "reason": "account_not_found",
        }

    db = supabase()

    # Prefer active row (since DB guarantees max one)
    sub = (
        db.table("user_subscriptions")
        .select("*")
        .eq("account_id", aid)
        .eq("is_active", True)
        .limit(1)
        .execute()
    )

    row = sub.data[0] if sub.data else None

    # If none active, get latest history row (optional)
    if not row:
        hist = (
            db.table("user_subscriptions")
            .select("*")
            .eq("account_id", aid)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        row = hist.data[0] if hist.data else None

    if not row:
        return {
            "active": False,
            "account_id": aid,
            "plan_code": None,
            "expires_at": None,
            "in_grace": False,
            "reason": "no_subscription",
        }

    plan_code = row.get("plan_code") or "unknown"
    expires_at = row.get("expires_at")
    is_active_flag = bool(row.get("is_active"))
    status = (row.get("status") or "").lower()

    plan = _get_plan(plan_code) or {}
    grace_days = int(plan.get("grace_days", 0))

    # If subscription is marked inactive, allow only grace window if you want “soft access”
    # Here’s the rule:
    # - If is_active = True => access window based on expires+grace
    # - If is_active = False => no access (even if expires in future) unless you explicitly want grace on inactive.
    # We'll keep strict: inactive means no.
    in_window = _is_within_access_window(expires_at, grace_days)

    active = bool(is_active_flag and in_window and status in ("active", "trial", "grace", ""))

    in_grace = False
    if expires_at:
        dt = _parse_iso(expires_at) if isinstance(expires_at, str) else None
        if dt:
            in_grace = (dt < _now_utc() <= (dt + timedelta(days=grace_days)))

    reason = "ok" if active else "inactive_or_expired"
    if in_grace and not active:
        # This only happens if you later decide to flip logic
        reason = "in_grace"

    return {
        "active": active,
        "account_id": aid,
        "plan_code": plan_code,
        "expires_at": expires_at,
        "in_grace": in_grace,
        "grace_days": grace_days,
        "status": row.get("status"),
        "reason": reason,
    }

def activate_subscription(
    account_id: str,
    plan_code: str,
    provider: str = "manual",
    reference: Optional[str] = None,
    expires_at: Optional[str] = None,
    event_type: str = "activated",
    extra_payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Create a NEW active subscription row (history preserved),
    while deactivating previous active subscription.

    This is the correct long-run approach for upgrades/downgrades/renewals.
    """
    now = _now_utc()

    # Deactivate existing active, keep for history
    prev = _deactivate_current_active(account_id, reason_status="replaced")

    # Compute expiry if not provided
    if expires_at:
        exp_dt = _parse_iso(expires_at)
        if not exp_dt:
            exp_dt, _ = _compute_expiry(plan_code, now=now)
    else:
        exp_dt, _ = _compute_expiry(plan_code, now=now)

    payload = {
        "account_id": account_id,
        "plan_code": plan_code,
        "is_active": True,
        "status": "trial" if (plan_code == "trial") else "active",
        "started_at": _iso_z(now),
        "expires_at": _iso_z(exp_dt),
        "updated_at": _iso_z(now),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    new_row = ins.data[0]

    _log_event(
        account_id=account_id,
        event_type=event_type,
        from_plan=(prev.get("plan_code") if prev else None),
        to_plan=plan_code,
        provider=provider,
        reference=reference,
        payload={"prev": prev, "new": new_row, **(extra_payload or {})},
    )
    return new_row

def start_trial(account_id: str, trial_days: Optional[int] = None) -> Dict[str, Any]:
    """
    One trial per account (enforced at app-level + event log check).
    """
    db = supabase()

    # Has user ever started a trial?
    already = (
        db.table("subscription_events")
        .select("id")
        .eq("account_id", account_id)
        .eq("event_type", "trial_started")
        .limit(1)
        .execute()
    )
    if already.data:
        return {"ok": False, "error": "trial_already_used"}

    plan = _get_plan("trial") or {}
    days = trial_days or int(plan.get("trial_days") or plan.get("duration_days") or 7)
    exp = _now_utc() + timedelta(days=days)

    row = activate_subscription(
        account_id=account_id,
        plan_code="trial",
        provider="system",
        expires_at=_iso_z(exp),
        event_type="trial_started",
        extra_payload={"trial_days": days},
    )
    return {"ok": True, "subscription": row}

def change_plan(account_id: str, new_plan_code: str, change_type: str = "upgraded") -> Dict[str, Any]:
    """
    Simple upgrade/downgrade:
    - Deactivate current active
    - Insert new active with full duration of new plan (no proration in v1)
    """
    row = activate_subscription(
        account_id=account_id,
        plan_code=new_plan_code,
        provider="manual",
        event_type=change_type,
        extra_payload={"change_type": change_type},
    )
    return {"ok": True, "subscription": row}

# -------------------------------
# Webhook-ready payment flow
# -------------------------------

def record_payment_initiated(account_id: str, provider: str, reference: str, plan_code: str, amount_kobo: Optional[int] = None, currency: str = "NGN") -> None:
    db = supabase()
    db.table("payments").upsert({
        "account_id": account_id,
        "provider": provider,
        "reference": reference,
        "plan_code": plan_code,
        "amount_kobo": amount_kobo,
        "currency": currency,
        "status": "initiated",
        "updated_at": _iso_z(_now_utc()),
    }, on_conflict="provider,reference").execute()

def handle_payment_success(provider: str, reference: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given a successful payment webhook payload, activate subscription.
    We resolve:
      - account_id
      - plan_code
    using (best practice): metadata embedded during init transaction.
    """
    db = supabase()

    # Read payment row (if initiated)
    p = (
        db.table("payments")
        .select("*")
        .eq("provider", provider)
        .eq("reference", reference)
        .limit(1)
        .execute()
    )
    pay_row = p.data[0] if p.data else None

    # Try resolving from metadata if missing
    meta = None
    try:
        meta = (payload.get("data") or {}).get("metadata") or {}
    except Exception:
        meta = {}

    account_id = (pay_row or {}).get("account_id") or meta.get("account_id")
    plan_code = (pay_row or {}).get("plan_code") or meta.get("plan_code")

    if not account_id or not plan_code:
        # Record raw and stop (you can reconcile manually)
        db.table("payments").upsert({
            "provider": provider,
            "reference": reference,
            "status": "success",
            "raw": payload,
            "updated_at": _iso_z(_now_utc()),
        }, on_conflict="provider,reference").execute()
        return {"ok": False, "error": "missing_account_or_plan"}

    # Mark payment success
    db.table("payments").upsert({
        "account_id": account_id,
        "provider": provider,
        "reference": reference,
        "plan_code": plan_code,
        "status": "success",
        "paid_at": _iso_z(_now_utc()),
        "raw": payload,
        "updated_at": _iso_z(_now_utc()),
    }, on_conflict="provider,reference").execute()

    # Activate subscription based on paid plan
    sub = activate_subscription(
        account_id=account_id,
        plan_code=plan_code,
        provider=provider,
        reference=reference,
        event_type="webhook_payment",
        extra_payload={"webhook": payload},
    )

    return {"ok": True, "subscription": sub}
