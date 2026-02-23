# app/services/subscriptions_service.py
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, List

from ..core.supabase_client import supabase


_PLAN_DAYS: Dict[str, int] = {
    "monthly": 30,
    "quarterly": 90,
    "yearly": 365,
}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _norm_plan(plan_code: Optional[str]) -> str:
    return (plan_code or "").strip().lower()


def _duration_days(plan_code: str) -> int:
    return _PLAN_DAYS.get(plan_code, 30)


def _rootcause(where: str, e: Exception, *, hint: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"where": where, "type": type(e).__name__, "message": str(e)}
    if hint:
        out["hint"] = hint
    if extra:
        out["extra"] = extra
    return out


def _ok(data: Dict[str, Any]) -> Dict[str, Any]:
    return {"ok": True, **data}


def _fail(
    error: str,
    *,
    where: str,
    e: Optional[Exception] = None,
    hint: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"ok": False, "error": error, "where": where}
    if e is not None:
        payload["root_cause"] = _rootcause(where, e, hint=hint, extra=extra)
    else:
        payload["root_cause"] = {"where": where, "message": hint or "unknown"}
        if extra:
            payload["root_cause"]["extra"] = extra
    return payload


def _db():
    return supabase()


# -----------------------------------------------------------------------------
# Accounts prerequisite (FK safety)
# Your schema: user_subscriptions.account_id (uuid) -> accounts.id (uuid)
# -----------------------------------------------------------------------------
def _account_exists(account_id: str) -> Tuple[bool, bool, Optional[Dict[str, Any]]]:
    account_id = (account_id or "").strip()
    try:
        db = _db()
        res = db.table("accounts").select("id").eq("id", account_id).limit(1).execute()
        rows = getattr(res, "data", None) or []
        return True, bool(rows), None
    except Exception as e:
        return False, False, _rootcause(
            "accounts.select",
            e,
            hint="Failed to read accounts table. Check Supabase credentials and RLS policies.",
            extra={"account_id": account_id, "expected_pk": "accounts.id"},
        )


def _ensure_account_exists(account_id: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
    ok, exists, err = _account_exists(account_id)
    if not ok:
        return False, err
    if not exists:
        return False, {
            "where": "ensure_account_exists",
            "type": "ForeignKeyViolation",
            "message": f"account_id '{account_id}' does not exist in accounts.id, so user_subscriptions cannot reference it.",
            "hint": "Create/login the account first (OTP flow) so it is inserted into accounts, then retry activation.",
            "extra": {"account_id": account_id, "required_table": "accounts", "fk": "user_subscriptions.account_id -> accounts.id"},
        }
    return True, None


# -----------------------------------------------------------------------------
# user_subscriptions helpers (match your real schema)
# -----------------------------------------------------------------------------
_SUB_SELECT = (
    "id, account_id, plan_code, status, started_at, expires_at, grace_until, trial_until, "
    "is_active, pending_plan_code, pending_starts_at, provider, provider_ref, created_at, updated_at"
)


def _get_user_subscription(account_id: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    account_id = (account_id or "").strip()
    try:
        db = _db()
        res = db.table("user_subscriptions").select(_SUB_SELECT).eq("account_id", account_id).limit(1).execute()
        rows = getattr(res, "data", None) or []
        row = rows[0] if rows else None
        return True, row, None
    except Exception as e:
        return False, None, _rootcause(
            "user_subscriptions.select",
            e,
            hint="Read failed. Check RLS policy for user_subscriptions and service role key usage.",
            extra={"account_id": account_id},
        )


def _upsert_user_subscription(payload: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        db = _db()
        db.table("user_subscriptions").upsert(payload, on_conflict="account_id").execute()

        ok, row, err = _get_user_subscription(payload.get("account_id") or "")
        if not ok:
            return False, None, err
        return True, row, None
    except Exception as e:
        return False, None, _rootcause(
            "user_subscriptions.upsert",
            e,
            hint="Upsert failed. Common causes: FK missing accounts row, RLS denies, or wrong Supabase key.",
            extra={"on_conflict": "account_id", "payload_keys": sorted(list(payload.keys()))},
        )


# -----------------------------------------------------------------------------
# Public service functions
# -----------------------------------------------------------------------------
def activate_subscription_now(
    *,
    account_id: str,
    plan_code: str,
    days: Optional[int] = None,
    status: str = "active",
    provider: Optional[str] = None,
    reference: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Idempotent activation:
      - Upserts by account_id (unique exists)
      - Sets is_active true
      - Stores provider/provider_ref if supplied
    """
    where = "activate_subscription_now"

    account_id = (account_id or "").strip()
    plan_code = _norm_plan(plan_code)
    status = (status or "active").strip().lower()

    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")
    if not plan_code:
        return _fail("missing_plan_code", where=where, hint="plan_code is required")

    ok_acc, acc_err = _ensure_account_exists(account_id)
    if not ok_acc:
        return {"ok": False, "error": "account_not_found", "where": where, "root_cause": acc_err}

    now = _now_utc()
    dur = int(days) if days is not None else _duration_days(plan_code)
    expires_at = now + timedelta(days=dur)

    # Keep started_at stable: if row exists, we don't want to overwrite it.
    ok_existing, existing, _ = _get_user_subscription(account_id)

    payload: Dict[str, Any] = {
        "account_id": account_id,
        "plan_code": plan_code,
        "status": status,
        "expires_at": _iso(expires_at),
        "grace_until": None,
        "trial_until": None,
        "is_active": True,
        "updated_at": _iso(now),
    }

    if not existing:
        payload["started_at"] = _iso(now)

    if provider:
        payload["provider"] = provider.strip().lower()
    if reference:
        payload["provider_ref"] = reference.strip()

    ok, row, err = _upsert_user_subscription(payload)
    if not ok:
        return {
            "ok": False,
            "error": "db_upsert_failed",
            "where": where,
            "root_cause": err,
            "table": "user_subscriptions",
            "attempted_payload_keys": sorted(list(payload.keys())),
        }

    return _ok({"account_id": account_id, "subscription": row})


def cancel_subscription(*, account_id: str, status: str = "canceled") -> Dict[str, Any]:
    where = "cancel_subscription"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    ok_acc, acc_err = _ensure_account_exists(account_id)
    if not ok_acc:
        return {"ok": False, "error": "account_not_found", "where": where, "root_cause": acc_err}

    now = _now_utc()
    payload = {"account_id": account_id, "status": (status or "canceled").strip().lower(), "is_active": False, "updated_at": _iso(now)}

    ok, row, err = _upsert_user_subscription(payload)
    if not ok:
        return {"ok": False, "error": "db_upsert_failed", "where": where, "root_cause": err}

    return _ok({"account_id": account_id, "subscription": row})


def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    where = "debug_read_subscription"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    ok, row, err = _get_user_subscription(account_id)
    if not ok:
        return {"ok": False, "error": "db_read_failed", "where": where, "root_cause": err}

    return _ok({"account_id": account_id, "subscription": row})


# -----------------------------------------------------------------------------
# Overdue expiry (matches your columns)
# -----------------------------------------------------------------------------
def expire_overdue_subscriptions(*, limit: int = 500) -> Dict[str, Any]:
    """
    Overdue = is_active true AND expires_at < now AND (grace_until is null OR grace_until < now)
    Action  = set status='expired', is_active=false, updated_at=now
    """
    where = "expire_overdue_subscriptions"
    now_iso = _iso(_now_utc())

    try:
        db = _db()
        res = (
            db.table("user_subscriptions")
            .select("id, account_id, status, expires_at, grace_until, is_active")
            .eq("is_active", True)
            .lt("expires_at", now_iso)
            .limit(int(limit))
            .execute()
        )
        rows: List[Dict[str, Any]] = getattr(res, "data", None) or []
    except Exception as e:
        return _fail("db_read_failed", where=where, e=e, hint="Failed to scan overdue subscriptions.")

    expired = 0
    skipped_grace = 0
    failed: List[Dict[str, Any]] = []

    for r in rows:
        sub_id = (r.get("id") or "").strip()
        grace_until = r.get("grace_until")

        # If grace_until exists and still in future => not overdue yet
        if grace_until:
            try:
                if str(grace_until) > str(now_iso):
                    skipped_grace += 1
                    continue
            except Exception:
                # conservative: if cannot compare, skip
                skipped_grace += 1
                continue

        try:
            db.table("user_subscriptions").update(
                {"status": "expired", "is_active": False, "updated_at": now_iso}
            ).eq("id", sub_id).execute()
            expired += 1
        except Exception as e:
            failed.append({"id": sub_id, "account_id": r.get("account_id"), "error": str(e)})

    return _ok({"expired": expired, "scanned": len(rows), "skipped_grace": skipped_grace, "failed": failed})


# -----------------------------------------------------------------------------
# Boot-safe compat shim used by ask_service (keep)
# -----------------------------------------------------------------------------
def get_subscription_status(account_id: str) -> Dict[str, Any]:
    where = "get_subscription_status(fallback)"
    account_id = (account_id or "").strip()
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    ok, row, err = _get_user_subscription(account_id)
    if not ok:
        return {"ok": False, "error": "db_read_failed", "where": where, "root_cause": err}

    if not row:
        return _ok({"account_id": account_id, "status": "free", "plan_code": None, "active": False})

    status = (row.get("status") or "").strip().lower() or "unknown"
    active = bool(row.get("is_active")) and status == "active"
    return _ok({"account_id": account_id, "status": status, "plan_code": row.get("plan_code"), "expires_at": row.get("expires_at"), "active": active})
