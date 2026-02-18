# app/services/subscriptions_service.py
from __future__ import annotations

from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta, timezone

from ..core.supabase_client import supabase
from ..services.credits_service import init_credits_for_plan
from ..services.subscription_status_service import get_subscription_status as _status_only


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


def _normalize_provider(provider: Optional[str]) -> Optional[str]:
    if not provider:
        return None
    p = provider.strip().lower()
    if p in ("whatsapp", "wa"):
        return "wa"
    if p in ("telegram", "tg"):
        return "tg"
    if p in ("web", "site", "website"):
        return "web"
    return p


# -----------------------------
# Lookups
# -----------------------------
def _find_account_id(account_id: Optional[str], provider: Optional[str], provider_user_id: Optional[str]) -> Optional[str]:
    if account_id:
        return account_id.strip() or None

    provider = _normalize_provider(provider)
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
    plan_code = (plan_code or "").strip().lower()
    if not plan_code:
        return None
    db = supabase()
    res = db.table("plans").select("*").eq("plan_code", plan_code).limit(1).execute()
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
# Public API (Back-compat)
# -----------------------------
def get_subscription_status(
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    BACKWARD-COMPAT:
    - Some routes call get_subscription_status(account_id=...)
    - Some older code calls get_subscription_status(account_id, provider, provider_user_id)

    We normalize to account_id then delegate to subscription_status_service (single truth).
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

    s = _status_only(aid)
    return {
        "active": bool(s.get("active")),
        "state": s.get("state") or "none",
        "account_id": aid,
        "plan_code": s.get("plan_code"),
        "expires_at": s.get("expires_at"),
        "grace_until": s.get("grace_until"),
        "reason": s.get("reason") or "ok",
    }


# -----------------------------
# Core mutations
# -----------------------------
def _deactivate_any_active(account_id: str, reason: str = "replaced") -> None:
    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return
    try:
        db.table("user_subscriptions").update(
            {"is_active": False, "status": reason, "updated_at": _iso(_now_utc())}
        ).eq("id", cur["id"]).execute()
    except Exception:
        try:
            db.table("user_subscriptions").update({"is_active": False}).eq("id", cur["id"]).execute()
        except Exception:
            pass


def _build_expiry_from_plan(plan_code: str, starts_at: datetime) -> datetime:
    plan = _get_plan(plan_code)
    duration_days = 30
    if plan:
        try:
            duration_days = int(plan.get("duration_days") or 30)
        except Exception:
            duration_days = 30
    return starts_at + timedelta(days=duration_days)


def _reset_ai_credits_best_effort(account_id: str, plan_code: str) -> None:
    try:
        init_credits_for_plan(account_id=account_id, plan_code=plan_code)
    except Exception:
        pass


def activate_subscription_now(account_id: str, plan_code: str, *, status: str = "active") -> Dict[str, Any]:
    account_id = (account_id or "").strip()
    plan_code = (plan_code or "").strip().lower()
    if not account_id or not plan_code:
        raise ValueError("account_id and plan_code are required")

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
        "pending_plan_code": None,
        "pending_starts_at": None,
        "updated_at": _iso(_now_utc()),
    }

    db = supabase()
    ins = db.table("user_subscriptions").insert(payload).execute()
    row = ins.data[0] if ins.data else payload

    _reset_ai_credits_best_effort(account_id, plan_code)
    return row


def schedule_plan_change_at_expiry(account_id: str, next_plan_code: str) -> Dict[str, Any]:
    account_id = (account_id or "").strip()
    next_plan_code = (next_plan_code or "").strip().lower()
    if not account_id or not next_plan_code:
        raise ValueError("account_id and next_plan_code are required")

    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return activate_subscription_now(account_id, next_plan_code, status="active")

    exp_dt = _parse_iso(cur.get("expires_at") or "") if isinstance(cur.get("expires_at"), str) else None
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
    return upd.data[0] if upd.data else cur


def apply_scheduled_change_if_due(account_id: str) -> Optional[Dict[str, Any]]:
    account_id = (account_id or "").strip()
    if not account_id:
        return None

    db = supabase()
    cur = _get_active_sub_row(account_id)
    if not cur:
        return None

    pending_plan = (cur.get("pending_plan_code") or "").strip().lower()
    pending_starts_at = cur.get("pending_starts_at")

    if not pending_plan or not pending_starts_at:
        return None

    starts_dt = _parse_iso(pending_starts_at) if isinstance(pending_starts_at, str) else None
    if not starts_dt:
        return None

    if _now_utc() < starts_dt:
        return None

    try:
        db.table("user_subscriptions").update(
            {"pending_plan_code": None, "pending_starts_at": None, "updated_at": _iso(_now_utc())}
        ).eq("id", cur["id"]).execute()
    except Exception:
        pass

    return activate_subscription_now(account_id, pending_plan, status="active")


# -----------------------------
# Expiry maintenance (Cron job)
# -----------------------------
def expire_overdue_subscriptions(*, batch_limit: int = 1000) -> Dict[str, Any]:
    db = supabase()
    now_iso = _iso(_now_utc())

    res = (
        db.table("user_subscriptions")
        .select("id")
        .eq("is_active", True)
        .lt("expires_at", now_iso)
        .limit(int(batch_limit))
        .execute()
    )

    ids = [r.get("id") for r in (res.data or []) if r.get("id")]
    if not ids:
        return {"ok": True, "expired": 0}

    try:
        db.table("user_subscriptions").update(
            {"is_active": False, "status": "expired", "updated_at": now_iso}
        ).in_("id", ids).execute()
    except Exception:
        try:
            db.table("user_subscriptions").update({"is_active": False}).in_("id", ids).execute()
        except Exception:
            return {"ok": False, "expired": 0, "error": "update_failed"}

    return {"ok": True, "expired": len(ids)}
