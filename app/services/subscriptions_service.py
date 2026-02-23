# app/services/subscriptions_service.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from app.core.supabase_client import supabase
from app.services.plans_service import get_plan


# -----------------------------
# Helpers
# -----------------------------
def _sb():
    return supabase() if callable(supabase) else supabase


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _err(code: str, message: str, *, root_cause: Optional[Exception] = None, extra: Optional[Dict[str, Any]] = None):
    out: Dict[str, Any] = {"ok": False, "error": code, "message": message}
    if extra:
        out["extra"] = extra
    if root_cause:
        out["root_cause"] = {"type": root_cause.__class__.__name__, "message": str(root_cause)}
    return out


def _duration_days_for_plan(plan_code: str, plan: Optional[Dict[str, Any]] = None) -> int:
    """
    We don’t know your exact plans schema, so we support common shapes:
    - plan["duration_days"]
    - plan["interval"] in {"monthly","quarterly","yearly"}
    - fallback mapping by plan_code
    """
    p = plan or get_plan(plan_code) or {}

    dd = p.get("duration_days")
    if isinstance(dd, int) and dd > 0:
        return dd

    interval = (p.get("interval") or "").strip().lower()
    if interval == "monthly":
        return 30
    if interval == "quarterly":
        return 90
    if interval == "yearly":
        return 365

    code = (plan_code or "").strip().lower()
    if code in {"monthly", "month"}:
        return 30
    if code in {"quarterly", "quarter"}:
        return 90
    if code in {"yearly", "annual", "year"}:
        return 365

    # safe default
    return 30


def _ensure_accounts_row_exists(account_id: str, *, provider: str = "web", provider_user_id: str = "", display_name: str = ""):
    """
    IMPORTANT:
      Your FK is user_subscriptions.account_id -> accounts.id

    So we must ensure accounts.id == account_id exists.
    """
    if not account_id:
        return

    try:
        res = _sb().table("accounts").select("id").eq("id", account_id).limit(1).execute()
        rows = (res.data or []) if hasattr(res, "data") else []
        if rows:
            return

        payload = {
            "id": account_id,  # ✅ THIS is what satisfies the FK
            "provider": provider or "web",
            "provider_user_id": provider_user_id or account_id,
            "display_name": display_name or provider_user_id or "Web User",
        }

        _sb().table("accounts").insert(payload).execute()
    except Exception:
        # best-effort only
        return


# -----------------------------
# Public API (ROUTES IMPORT THESE)
# -----------------------------
def activate_subscription_now(
    *,
    account_id: str,
    plan_code: str,
    status: str = "active",
    provider: Optional[str] = None,
    provider_ref: Optional[str] = None,
    started_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Creates/updates the single subscription row per account (unique account_id).
    Sets is_active=true and expires_at based on plan duration.
    """
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip().lower()
    status = (status or "active").strip().lower()

    if not account_id:
        raise ValueError("missing_account_id")
    if not plan_code:
        raise ValueError("missing_plan_code")

    plan = get_plan(plan_code)
    if not plan:
        raise ValueError(f"invalid_plan_code:{plan_code}")

    # Ensure FK parent exists
    _ensure_accounts_row_exists(account_id, provider=(provider or "web"))

    now = _utcnow()
    start = started_at or now
    days = _duration_days_for_plan(plan_code, plan=plan)
    expires_at = start + timedelta(days=days)

    row = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": status,
        "is_active": True,
        "started_at": start.isoformat(),
        "expires_at": expires_at.isoformat(),
        "updated_at": now.isoformat(),
        "provider": provider,
        "provider_ref": provider_ref,
        # keep grace_until/trial_until as-is unless you explicitly set them elsewhere
    }

    # Upsert by unique key (account_id)
    try:
        res = _sb().table("user_subscriptions").upsert(row, on_conflict="account_id").select("*").execute()
        rows = (res.data or []) if hasattr(res, "data") else []
        return rows[0] if rows else row
    except Exception as e:
        # root-cause exposer
        raise RuntimeError(f"activate_subscription_now_failed: {e}") from e


def get_subscription_status(account_id: str) -> Dict[str, Any]:
    """
    Returns computed status information used by other services/routes.
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return _err("missing_account_id", "account_id is required")

    try:
        res = (
            _sb()
            .table("user_subscriptions")
            .select("account_id, plan_code, status, is_active, started_at, expires_at, grace_until, trial_until, provider, provider_ref")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        sub = rows[0] if rows else None

        now = _utcnow()

        if not sub:
            return {
                "ok": True,
                "account_id": account_id,
                "exists": False,
                "status": "none",
                "is_active": False,
                "now_utc": now.isoformat(),
                "is_overdue": False,
            }

        expires_at = sub.get("expires_at")
        grace_until = sub.get("grace_until")
        trial_until = sub.get("trial_until")

        # Parse timestamps safely (Supabase may return ISO strings)
        def _parse_ts(v: Any) -> Optional[datetime]:
            if not v:
                return None
            if isinstance(v, datetime):
                return v.astimezone(timezone.utc)
            s = str(v).replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(s).astimezone(timezone.utc)
            except Exception:
                return None

        exp = _parse_ts(expires_at)
        grace = _parse_ts(grace_until)
        trial = _parse_ts(trial_until)

        is_active = bool(sub.get("is_active"))
        overdue = False

        # overdue if expired AND grace is either null or already passed
        if is_active and exp and now > exp and (grace is None or now > grace):
            overdue = True

        return {
            "ok": True,
            "exists": True,
            "account_id": account_id,
            "plan_code": sub.get("plan_code"),
            "status": sub.get("status"),
            "is_active": is_active,
            "started_at": sub.get("started_at"),
            "expires_at": sub.get("expires_at"),
            "grace_until": sub.get("grace_until"),
            "trial_until": sub.get("trial_until"),
            "provider": sub.get("provider"),
            "provider_ref": sub.get("provider_ref"),
            "now_utc": now.isoformat(),
            "is_overdue": overdue,
        }

    except Exception as e:
        return _err("subscription_status_failed", "could not read subscription", root_cause=e)


def handle_payment_success(*, reference: str, event: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Called by webhook route on charge.success.
    Activates subscription using metadata.account_id + metadata.plan_code.
    """
    reference = (reference or "").strip()
    if not reference:
        return _err("missing_reference", "reference is required")

    try:
        data = (event or {}).get("data") if isinstance(event, dict) else None
        if not isinstance(data, dict):
            data = {}

        md = data.get("metadata") or {}
        account_id = (md.get("account_id") or "").strip()
        plan_code = (md.get("plan_code") or "").strip().lower()

        if not account_id or not plan_code:
            return _err("missing_metadata", "missing account_id/plan_code in metadata", extra={"reference": reference})

        # best-effort: mark tx success if table exists
        try:
            _sb().table("paystack_transactions").update(
                {"status": "success", "paystack_status": "success", "raw": event or {}}
            ).eq("reference", reference).execute()
        except Exception:
            pass

        sub = activate_subscription_now(account_id=account_id, plan_code=plan_code, status="active", provider="paystack", provider_ref=reference)
        return {"ok": True, "reference": reference, "subscription": sub}

    except Exception as e:
        return _err("handle_payment_success_failed", "failed to process success event", root_cause=e, extra={"reference": reference})


def handle_payment_failed(*, reference: str, event: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Called by webhook route on charge.failed / transfer.failed etc.
    """
    reference = (reference or "").strip()
    if not reference:
        return _err("missing_reference", "reference is required")

    try:
        try:
            _sb().table("paystack_transactions").update(
                {"status": "failed", "paystack_status": "failed", "raw": event or {}}
            ).eq("reference", reference).execute()
        except Exception:
            pass

        return {"ok": True, "reference": reference, "status": "failed"}

    except Exception as e:
        return _err("handle_payment_failed_failed", "failed to process failed event", root_cause=e, extra={"reference": reference})

def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    """
    Debug helper used by routes/subscriptions.py.
    Returns the raw user_subscriptions row (if any) plus computed status.
    Safe to keep in prod but you can protect the route with admin auth later.
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "missing_account_id", "message": "account_id is required"}

    try:
        res = (
            _sb()
            .table("user_subscriptions")
            .select("*")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        row = rows[0] if rows else None

        status = get_subscription_status(account_id)

        return {
            "ok": True,
            "account_id": account_id,
            "subscription_row": row,
            "computed_status": status,
        }
    except Exception as e:
        return _err(
            "debug_read_subscription_failed",
            "could not read subscription for debug",
            root_cause=e,
            extra={"account_id": account_id},
        )
