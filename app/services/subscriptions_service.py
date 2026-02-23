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


def _db():
    # in your codebase, supabase is a factory function
    return supabase()


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


def _fail(error: str, *, where: str, e: Optional[Exception] = None, hint: Optional[str] = None, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"ok": False, "error": error, "where": where}
    if e is not None:
        payload["root_cause"] = _rootcause(where, e, hint=hint, extra=extra)
    else:
        payload["root_cause"] = {"where": where, "message": hint or "unknown"}
        if extra:
            payload["root_cause"]["extra"] = extra
    return payload


# -----------------------------------------------------------------------------
# Account resolution (CRITICAL)
# user_subscriptions.account_id FK -> accounts.id
# but your accounts table ALSO has accounts.account_id.
# We accept either input and resolve to accounts.id.
# -----------------------------------------------------------------------------
def _resolve_accounts_pk(account_id_or_public: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
    where = "resolve_accounts_pk"
    v = (account_id_or_public or "").strip()
    if not v:
        return False, None, {"where": where, "message": "missing_account_id"}

    try:
        db = _db()

        # 1) Treat input as accounts.id
        res1 = (
            db.table("accounts")
            .select("id, account_id")
            .eq("id", v)
            .limit(1)
            .execute()
        )
        rows1 = getattr(res1, "data", None) or []
        if rows1:
            return True, rows1[0]["id"], None

        # 2) Treat input as accounts.account_id
        res2 = (
            db.table("accounts")
            .select("id, account_id")
            .eq("account_id", v)
            .limit(1)
            .execute()
        )
        rows2 = getattr(res2, "data", None) or []
        if rows2:
            return True, rows2[0]["id"], None

        return False, None, {
            "where": where,
            "type": "AccountNotFound",
            "message": "No matching accounts row for provided account identifier.",
            "hint": "Ensure the user completed OTP/login first so accounts row exists, then retry.",
            "extra": {"provided": v, "tried": ["accounts.id", "accounts.account_id"]},
        }

    except Exception as e:
        return False, None, _rootcause(
            where,
            e,
            hint="Failed to read accounts. Check Supabase key and RLS.",
            extra={"provided": v},
        )


def _overdue_predicate_sql(now_iso: str) -> str:
    # used only for documentation/debug; we still do actual update with Supabase filters below
    return (
        "is_active = true AND expires_at IS NOT NULL AND "
        f"'{now_iso}'::timestamptz > expires_at AND "
        "(grace_until IS NULL OR '{now_iso}'::timestamptz > grace_until)"
    )


def _get_user_subscription(account_pk: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        db = _db()
        res = (
            db.table("user_subscriptions")
            .select(
                "id, account_id, plan_code, status, is_active, started_at, expires_at, grace_until, trial_until, provider, provider_ref, created_at, updated_at"
            )
            .eq("account_id", account_pk)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return True, (rows[0] if rows else None), None
    except Exception as e:
        return False, None, _rootcause(
            "user_subscriptions.select",
            e,
            hint="Read failed. Check RLS/service role key.",
            extra={"account_id": account_pk},
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
            hint="Upsert failed. Likely FK mismatch (accounts.id) or RLS denial.",
            extra={"on_conflict": "account_id", "payload_keys": sorted(list(payload.keys()))},
        )


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
def activate_subscription_now(
    *,
    account_id: str,
    plan_code: str,
    days: Optional[int] = None,
    status: str = "active",
    provider: Optional[str] = None,
    provider_ref: Optional[str] = None,
) -> Dict[str, Any]:
    where = "activate_subscription_now"

    plan_code = _norm_plan(plan_code)
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")
    if not plan_code:
        return _fail("missing_plan_code", where=where, hint="plan_code is required")

    ok_pk, account_pk, err = _resolve_accounts_pk(account_id)
    if not ok_pk or not account_pk:
        return {"ok": False, "error": "account_not_found", "where": where, "root_cause": err}

    now = _now_utc()
    dur = int(days) if days is not None else _duration_days(plan_code)
    expires_at = now + timedelta(days=dur)

    payload: Dict[str, Any] = {
        "account_id": account_pk,              # ✅ FK-safe: accounts.id
        "plan_code": plan_code,
        "status": (status or "active").strip().lower(),
        "is_active": True,
        "started_at": _iso(now),
        "expires_at": _iso(expires_at),
        "grace_until": None,
        "trial_until": None,
        "provider": provider,
        "provider_ref": provider_ref,
        "updated_at": _iso(now),
    }

    ok, row, upsert_err = _upsert_user_subscription(payload)
    if not ok:
        return {
            "ok": False,
            "error": "db_upsert_failed",
            "where": where,
            "root_cause": upsert_err,
            "table": "user_subscriptions",
            "attempted_payload_keys": sorted(list(payload.keys())),
        }

    return _ok({"account_id": account_pk, "subscription": row})


def cancel_subscription(*, account_id: str, status: str = "canceled") -> Dict[str, Any]:
    where = "cancel_subscription"
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    ok_pk, account_pk, err = _resolve_accounts_pk(account_id)
    if not ok_pk or not account_pk:
        return {"ok": False, "error": "account_not_found", "where": where, "root_cause": err}

    now = _now_utc()
    payload = {
        "account_id": account_pk,
        "status": (status or "canceled").strip().lower(),
        "is_active": False,
        "updated_at": _iso(now),
    }

    ok, row, upsert_err = _upsert_user_subscription(payload)
    if not ok:
        return {"ok": False, "error": "db_upsert_failed", "where": where, "root_cause": upsert_err}

    return _ok({"account_id": account_pk, "subscription": row})


def debug_read_subscription(account_id: str) -> Dict[str, Any]:
    where = "debug_read_subscription"
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    ok_pk, account_pk, err = _resolve_accounts_pk(account_id)
    if not ok_pk or not account_pk:
        return {"ok": False, "error": "account_not_found", "where": where, "root_cause": err}

    ok, row, read_err = _get_user_subscription(account_pk)
    if not ok:
        return {"ok": False, "error": "db_read_failed", "where": where, "root_cause": read_err}

    return _ok({"account_id": account_pk, "subscription": row})


# -----------------------------------------------------------------------------
# Overdue handling (fixes your cron import error)
# Overdue rule:
#   is_active=true AND expires_at not null AND now>expires_at AND (grace_until null OR now>grace_until)
# -----------------------------------------------------------------------------
def expire_overdue_subscriptions(*, mark_status: str = "past_due") -> Dict[str, Any]:
    where = "expire_overdue_subscriptions"
    now = _now_utc()
    now_iso = _iso(now) or _iso(datetime.now(timezone.utc))  # safety

    try:
        db = _db()

        # Query overdue rows first (so we can return count deterministically)
        res = (
            db.table("user_subscriptions")
            .select("id, account_id, status, is_active, expires_at, grace_until")
            .eq("is_active", True)
            .not_.is_("expires_at", "null")
            .lt("expires_at", now_iso)
            .or_(f"grace_until.is.null,grace_until.lt.{now_iso}")
            .execute()
        )
        rows: List[Dict[str, Any]] = getattr(res, "data", None) or []
        if not rows:
            return _ok({"updated": 0, "rule": _overdue_predicate_sql(now_iso)})

        # Mark them
        ids = [r["id"] for r in rows if r.get("id")]
        db.table("user_subscriptions").update(
            {"status": mark_status, "is_active": False, "updated_at": now_iso}
        ).in_("id", ids).execute()

        return _ok({"updated": len(ids), "rule": _overdue_predicate_sql(now_iso)})

    except Exception as e:
        return _fail(
            "expire_failed",
            where=where,
            e=e,
            hint="Failed to mark overdue subs. Check RLS/service role key.",
            extra={"rule": _overdue_predicate_sql(now_iso)},
        )


# -----------------------------------------------------------------------------
# Compatibility shim: get_subscription_status
# -----------------------------------------------------------------------------
def get_subscription_status(account_id: str) -> Dict[str, Any]:
    where = "get_subscription_status"
    if not account_id:
        return _fail("missing_account_id", where=where, hint="account_id is required")

    ok_pk, account_pk, err = _resolve_accounts_pk(account_id)
    if not ok_pk or not account_pk:
        return {"ok": False, "error": "account_not_found", "where": where, "root_cause": err}

    ok, row, read_err = _get_user_subscription(account_pk)
    if not ok:
        return {"ok": False, "error": "db_read_failed", "where": where, "root_cause": read_err}

    if not row:
        return _ok({"account_id": account_pk, "status": "free", "plan_code": None, "active": False})

    status = (row.get("status") or "").strip().lower() or "unknown"
    is_active = bool(row.get("is_active")) and status == "active"
    return _ok({"account_id": account_pk, "status": status, "plan_code": row.get("plan_code"), "active": is_active, "expires_at": row.get("expires_at")})
