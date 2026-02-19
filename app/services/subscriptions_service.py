# app/services/subscriptions_service.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, List

from ..core.supabase_client import supabase

# ============================================================
# Time helpers
# ============================================================

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ============================================================
# Supabase client compatibility
# (supports both `supabase()` and `supabase.table(...)`)
# ============================================================

def _sb():
    try:
        # factory style
        return supabase()
    except TypeError:
        # direct client style
        return supabase

def _table(name: str):
    return _sb().table(name)


# ============================================================
# Public Types
# ============================================================

@dataclass
class SubStatus:
    account_id: Optional[str]
    active: bool
    expires_at: Optional[str]
    grace_until: Optional[str]
    plan_code: Optional[str]
    reason: str
    state: str  # "none" | "active" | "grace" | "expired"


# ============================================================
# Internal lookups
# ============================================================

def _find_account_id(
    account_id: Optional[str],
    provider: Optional[str],
    provider_user_id: Optional[str],
) -> Optional[str]:
    """
    If account_id is provided -> use it.
    Else try to find account by (provider, provider_user_id) from accounts table.
    """
    if account_id and account_id.strip():
        return account_id.strip()

    if not provider or not provider_user_id:
        return None

    try:
        res = (
            _table("accounts")
            .select("account_id")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if rows:
            return (rows[0].get("account_id") or "").strip() or None
        return None
    except Exception:
        return None


def _get_latest_subscription_row(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Reads latest subscription row for account_id.
    Tries common table/column patterns.
    """
    # Common table name:
    # - "subscriptions"
    # You can rename if yours differs, but keep as-is for current architecture.
    try:
        res = (
            _table("subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return rows[0] if rows else None
    except Exception:
        return None


def _get_plan_duration_days(plan_code: str) -> Optional[int]:
    """
    Optional: looks up duration_days from plans table (if you use it).
    Safe if table doesn't exist.
    """
    try:
        res = (
            _table("plans")
            .select("duration_days")
            .eq("plan_code", plan_code)
            .eq("active", True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return None
        v = rows[0].get("duration_days")
        return int(v) if v is not None else None
    except Exception:
        return None


# ============================================================
# Core: status normalization (single source of truth)
# ============================================================

def get_subscription_status(
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Returns normalized subscription state for an account.
    Output shape matches what frontend + ask_guarded() typically expect.

    States:
      - none: no sub row or inactive
      - active: now <= expires_at
      - grace: expires_at < now <= grace_until
      - expired: now > grace_until (or expired and no grace)
    """
    acc_id = _find_account_id(account_id, provider, provider_user_id)
    if not acc_id:
        return {
            "account_id": None,
            "active": False,
            "expires_at": None,
            "grace_until": None,
            "plan_code": None,
            "reason": "no_account",
            "state": "none",
        }

    row = _get_latest_subscription_row(acc_id)
    if not row:
        return {
            "account_id": acc_id,
            "active": False,
            "expires_at": None,
            "grace_until": None,
            "plan_code": None,
            "reason": "no_subscription",
            "state": "none",
        }

    # Support common column names:
    plan_code = row.get("plan_code") or row.get("plan") or row.get("tier")
    active_flag = bool(row.get("active", True))

    expires_at = _parse_iso(row.get("expires_at") or row.get("ends_at"))
    grace_until = _parse_iso(row.get("grace_until") or row.get("grace_ends_at"))

    now = _now_utc()

    # If explicitly inactive
    if not active_flag:
        return {
            "account_id": acc_id,
            "active": False,
            "expires_at": _iso(expires_at) if expires_at else None,
            "grace_until": _iso(grace_until) if grace_until else None,
            "plan_code": plan_code,
            "reason": "inactive",
            "state": "none",
        }

    # If no expiry date, treat as none (safer than infinite access)
    if not expires_at:
        return {
            "account_id": acc_id,
            "active": False,
            "expires_at": None,
            "grace_until": _iso(grace_until) if grace_until else None,
            "plan_code": plan_code,
            "reason": "missing_expires_at",
            "state": "none",
        }

    if now <= expires_at:
        return {
            "account_id": acc_id,
            "active": True,
            "expires_at": _iso(expires_at),
            "grace_until": _iso(grace_until) if grace_until else None,
            "plan_code": plan_code,
            "reason": "active",
            "state": "active",
        }

    # expired but maybe within grace
    if grace_until and now <= grace_until:
        return {
            "account_id": acc_id,
            "active": True,
            "expires_at": _iso(expires_at),
            "grace_until": _iso(grace_until),
            "plan_code": plan_code,
            "reason": "grace",
            "state": "grace",
        }

    # fully expired
    return {
        "account_id": acc_id,
        "active": False,
        "expires_at": _iso(expires_at),
        "grace_until": _iso(grace_until) if grace_until else None,
        "plan_code": plan_code,
        "reason": "expired",
        "state": "expired",
    }


# ============================================================
# Optional: Trial
# ============================================================

def start_trial_if_eligible(account_id: str, trial_days: int = 7) -> Dict[str, Any]:
    """
    Activates a trial if user has no active subscription.
    Safe implementation: only creates/updates subscription row if none exists.
    """
    acc_id = (account_id or "").strip()
    if not acc_id:
        return {"ok": False, "error": "missing_account_id"}

    st = get_subscription_status(account_id=acc_id)
    if st.get("state") in ("active", "grace"):
        return {"ok": True, "skipped": True, "reason": "already_active"}

    now = _now_utc()
    expires = now + timedelta(days=max(1, int(trial_days)))
    grace = expires + timedelta(days=1)

    payload = {
        "account_id": acc_id,
        "plan_code": "trial",
        "active": True,
        "expires_at": _iso(expires),
        "grace_until": _iso(grace),
        "source": "trial",
        "updated_at": _iso(now),
        "created_at": _iso(now),
    }

    try:
        # Upsert by account_id if your schema supports it; otherwise insert.
        # We attempt upsert first; if it fails, fallback to insert.
        try:
            _table("subscriptions").upsert(payload, on_conflict="account_id").execute()
        except Exception:
            _table("subscriptions").insert(payload).execute()
        return {"ok": True, "trial": True, "expires_at": payload["expires_at"]}
    except Exception as e:
        return {"ok": False, "error": f"trial_activation_failed: {e}"}


# ============================================================
# Activation after payment
# ============================================================

def activate_subscription_now(
    account_id: str,
    plan_code: str,
    duration_days: Optional[int] = None,
    grace_days: int = 1,
    source: str = "payment",
    reference: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Immediate activation after successful payment.
    If duration_days not provided, tries plans table.
    """
    acc_id = (account_id or "").strip()
    if not acc_id:
        return {"ok": False, "error": "missing_account_id"}
    plan_code = (plan_code or "").strip()
    if not plan_code:
        return {"ok": False, "error": "missing_plan_code"}

    if duration_days is None:
        duration_days = _get_plan_duration_days(plan_code)

    if not duration_days:
        # safe default to 30 days if you didn't define plans table yet
        duration_days = 30

    now = _now_utc()
    expires = now + timedelta(days=int(duration_days))
    grace = expires + timedelta(days=max(0, int(grace_days)))

    payload = {
        "account_id": acc_id,
        "plan_code": plan_code,
        "active": True,
        "expires_at": _iso(expires),
        "grace_until": _iso(grace),
        "source": source,
        "reference": reference,
        "updated_at": _iso(now),
    }

    try:
        try:
            _table("subscriptions").upsert(payload, on_conflict="account_id").execute()
        except Exception:
            # fallback: insert a new row (if your schema is append-only)
            payload["created_at"] = _iso(now)
            _table("subscriptions").insert(payload).execute()

        return {
            "ok": True,
            "account_id": acc_id,
            "plan_code": plan_code,
            "expires_at": payload["expires_at"],
            "grace_until": payload["grace_until"],
        }
    except Exception as e:
        return {"ok": False, "error": f"activate_failed: {e}"}


def schedule_plan_change_at_expiry(
    account_id: str,
    new_plan_code: str,
) -> Dict[str, Any]:
    """
    Stores requested plan change to be applied later by cron.
    Safe approach: writes fields on subscription row if columns exist.
    If your DB doesn't have these columns yet, it won't crash; it returns an error.
    """
    acc_id = (account_id or "").strip()
    new_plan_code = (new_plan_code or "").strip()
    if not acc_id or not new_plan_code:
        return {"ok": False, "error": "missing_account_id_or_plan"}

    now = _now_utc()
    try:
        res = (
            _table("subscriptions")
            .update(
                {
                    "pending_plan_code": new_plan_code,
                    "pending_plan_set_at": _iso(now),
                    "updated_at": _iso(now),
                }
            )
            .eq("account_id", acc_id)
            .execute()
        )
        return {"ok": True, "updated": True, "data": getattr(res, "data", None)}
    except Exception as e:
        return {"ok": False, "error": f"schedule_change_failed: {e}"}


def manual_activate_subscription(
    account_id: str,
    plan_code: str,
    duration_days: int = 30,
    note: str = "manual",
) -> Dict[str, Any]:
    """
    Admin/manual activation.
    """
    return activate_subscription_now(
        account_id=account_id,
        plan_code=plan_code,
        duration_days=duration_days,
        grace_days=1,
        source="manual",
        reference=note,
    )


# ============================================================
# Webhook bridge (Paystack)
# ============================================================

def handle_payment_success(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Webhook bridge: extracts account_id + plan_code and activates subscription.
    Keep this conservative: if required fields aren't present, do nothing.
    """
    try:
        data = payload.get("data") or {}
        metadata = data.get("metadata") or {}

        account_id = (metadata.get("account_id") or metadata.get("user_id") or "").strip()
        plan_code = (metadata.get("plan_code") or metadata.get("plan") or "").strip()

        reference = (data.get("reference") or payload.get("reference") or "").strip() or None

        if not account_id or not plan_code:
            return {"ok": False, "error": "missing_account_id_or_plan_code_in_metadata"}

        return activate_subscription_now(
            account_id=account_id,
            plan_code=plan_code,
            duration_days=None,
            grace_days=1,
            source="paystack",
            reference=reference,
        )
    except Exception as e:
        return {"ok": False, "error": f"handle_payment_success_failed: {e}"}


# ============================================================
# CRON: expire overdue subscriptions (FIXES YOUR BOOT CRASH)
# ============================================================

def expire_overdue_subscriptions(limit: int = 500) -> Dict[str, Any]:
    """
    Called by /routes/cron.py

    Goal:
      - find subscriptions that are no longer valid (past grace_until or past expires_at if no grace)
      - mark them inactive

    Works even if you don't have perfect schema:
      - if update fails, returns error but will not crash the app
    """
    now = _now_utc()
    now_iso = _iso(now)

    # We attempt a simple approach:
    # 1) Pull a batch of 'active=true' subs
    # 2) Decide which are overdue
    # 3) Update them to active=false
    try:
        res = (
            _table("subscriptions")
            .select("account_id, active, expires_at, grace_until, updated_at, plan_code")
            .eq("active", True)
            .order("updated_at", desc=False)
            .limit(int(limit))
            .execute()
        )
        rows: List[Dict[str, Any]] = getattr(res, "data", None) or []
    except Exception as e:
        return {"ok": False, "error": f"fetch_subscriptions_failed: {e}", "expired": 0}

    overdue_accounts: List[str] = []
    for r in rows:
        expires_at = _parse_iso(r.get("expires_at"))
        grace_until = _parse_iso(r.get("grace_until"))
        if not expires_at:
            # If expiry is missing, safest is to deactivate
            overdue_accounts.append(r.get("account_id"))
            continue

        if grace_until:
            if now > grace_until:
                overdue_accounts.append(r.get("account_id"))
        else:
            if now > expires_at:
                overdue_accounts.append(r.get("account_id"))

    overdue_accounts = [a for a in overdue_accounts if a]

    if not overdue_accounts:
        return {"ok": True, "expired": 0, "checked": len(rows)}

    # Bulk update (best-effort). Supabase doesn't support "IN" everywhere the same way,
    # but `.in_()` exists in supabase-py v2.
    try:
        upd = (
            _table("subscriptions")
            .update({"active": False, "updated_at": now_iso})
            .in_("account_id", overdue_accounts)
            .execute()
        )
        updated_rows = getattr(upd, "data", None) or []
        return {"ok": True, "expired": len(overdue_accounts), "updated": len(updated_rows)}
    except Exception as e:
        # Fallback: update one-by-one (still safe; avoid total failure)
        success = 0
        errors: List[str] = []
        for acc in overdue_accounts:
            try:
                _table("subscriptions").update({"active": False, "updated_at": now_iso}).eq("account_id", acc).execute()
                success += 1
            except Exception as ee:
                errors.append(f"{acc}: {ee}")
        return {"ok": success > 0, "expired": len(overdue_accounts), "updated": success, "errors": errors[:10]}
