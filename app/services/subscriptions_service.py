# app/services/subscriptions_service.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, List

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
        return supabase()
    except TypeError:
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
    Table assumed: subscriptions
    """
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
    Optional: looks up duration_days from plans table (if present).
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
# Core: status normalization
# ============================================================

def get_subscription_status(
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Returns normalized subscription status.
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

    plan_code = row.get("plan_code") or row.get("plan") or row.get("tier")
    active_flag = bool(row.get("active", True))

    expires_at = _parse_iso(row.get("expires_at") or row.get("ends_at"))
    grace_until = _parse_iso(row.get("grace_until") or row.get("grace_ends_at"))

    now = _now_utc()

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

    if not expires_at:
        # safer than granting infinite access
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
# Trial
# ============================================================

def start_trial_if_eligible(account_id: str, trial_days: int = 7) -> Dict[str, Any]:
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
        try:
            _table("subscriptions").upsert(payload, on_conflict="account_id").execute()
        except Exception:
            _table("subscriptions").insert(payload).execute()
        return {"ok": True, "trial": True, "expires_at": payload["expires_at"]}
    except Exception as e:
        return {"ok": False, "error": f"trial_activation_failed: {e}"}


# ============================================================
# Activation / plan change
# ============================================================

def activate_subscription_now(
    account_id: str,
    plan_code: str,
    duration_days: Optional[int] = None,
    grace_days: int = 1,
    source: str = "payment",
    reference: Optional[str] = None,
) -> Dict[str, Any]:
    acc_id = (account_id or "").strip()
    if not acc_id:
        return {"ok": False, "error": "missing_account_id"}

    plan_code = (plan_code or "").strip()
    if not plan_code:
        return {"ok": False, "error": "missing_plan_code"}

    if duration_days is None:
        duration_days = _get_plan_duration_days(plan_code)

    if not duration_days:
        duration_days = 30  # safe default

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


def schedule_plan_change_at_expiry(account_id: str, new_plan_code: str) -> Dict[str, Any]:
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


def manual_activate_subscription(account_id: str, plan_code: str, duration_days: int = 30, note: str = "manual") -> Dict[str, Any]:
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
# CRON: expire overdue subscriptions
# ============================================================

def expire_overdue_subscriptions(batch_limit: int = 500) -> Dict[str, Any]:
    """
    Called by /routes/cron.py

    Finds subscriptions still marked active but past grace/expires.
    Marks them inactive.

    Returns:
      { ok, checked, expired, updated, errors? }
    """
    now = _now_utc()
    now_iso = _iso(now)

    # 1) Fetch a batch of active subs
    try:
        res = (
            _table("subscriptions")
            .select("account_id, active, expires_at, grace_until, updated_at, plan_code")
            .eq("active", True)
            .order("updated_at", desc=False)
            .limit(int(batch_limit))
            .execute()
        )
        rows: List[Dict[str, Any]] = getattr(res, "data", None) or []
    except Exception as e:
        return {"ok": False, "error": f"fetch_subscriptions_failed: {e}", "checked": 0, "expired": 0, "updated": 0}

    overdue_accounts: List[str] = []

    for r in rows:
        acc = r.get("account_id")
        expires_at = _parse_iso(r.get("expires_at"))
        grace_until = _parse_iso(r.get("grace_until"))

        # missing expires -> safest deactivate
        if not expires_at:
            if acc:
                overdue_accounts.append(acc)
            continue

        if grace_until:
            if now > grace_until and acc:
                overdue_accounts.append(acc)
        else:
            if now > expires_at and acc:
                overdue_accounts.append(acc)

    if not overdue_accounts:
        return {"ok": True, "checked": len(rows), "expired": 0, "updated": 0}

    # 2) Bulk update best-effort; fallback to per-row updates
    try:
        upd = (
            _table("subscriptions")
            .update({"active": False, "updated_at": now_iso})
            .in_("account_id", overdue_accounts)
            .execute()
        )
        updated_rows = getattr(upd, "data", None) or []
        return {
            "ok": True,
            "checked": len(rows),
            "expired": len(overdue_accounts),
            "updated": len(updated_rows),
        }
    except Exception as e:
        success = 0
        errors: List[str] = []
        for acc in overdue_accounts:
            try:
                _table("subscriptions").update({"active": False, "updated_at": now_iso}).eq("account_id", acc).execute()
                success += 1
            except Exception as ee:
                errors.append(f"{acc}: {ee}")

        return {
            "ok": success > 0,
            "checked": len(rows),
            "expired": len(overdue_accounts),
            "updated": success,
            "errors": errors[:10],
            "bulk_error": str(e),
        }
