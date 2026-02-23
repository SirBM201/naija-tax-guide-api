# app/services/subscription_status_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, List

from ..core.supabase_client import supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        v = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def _iso_or_none(value: Optional[str]) -> Optional[str]:
    return value if value else None


def _sanitize_err(e: Exception) -> str:
    """
    Safe error string:
    - no stack trace
    - short
    - does not include env values
    """
    s = str(e) or e.__class__.__name__
    s = s.replace("\n", " ").strip()
    return s[:280]


def _compute_state(
    *,
    now: datetime,
    plan_code: Optional[str],
    status: Optional[str],
    expires_at: Optional[str],
    grace_until: Optional[str],
    trial_until: Optional[str],
) -> Dict[str, Any]:
    status_norm = (status or "").strip().lower()
    exp_dt = _parse_iso(expires_at)
    grace_dt = _parse_iso(grace_until)
    trial_dt = _parse_iso(trial_until)

    explicitly_inactive = status_norm in {"canceled", "cancelled", "inactive", "disabled", "paused"}

    if trial_dt and trial_dt > now and not explicitly_inactive:
        return {
            "active": True,
            "state": "trial",
            "reason": "within_trial",
            "plan_code": plan_code,
            "expires_at": _iso_or_none(expires_at),
            "grace_until": _iso_or_none(grace_until),
            "trial_until": _iso_or_none(trial_until),
        }

    if exp_dt and exp_dt > now and not explicitly_inactive:
        return {
            "active": True,
            "state": "active",
            "reason": "within_expiry",
            "plan_code": plan_code,
            "expires_at": _iso_or_none(expires_at),
            "grace_until": _iso_or_none(grace_until),
            "trial_until": _iso_or_none(trial_until),
        }

    if grace_dt and grace_dt > now and not explicitly_inactive:
        return {
            "active": True,
            "state": "grace",
            "reason": "within_grace",
            "plan_code": plan_code,
            "expires_at": _iso_or_none(expires_at),
            "grace_until": _iso_or_none(grace_until),
            "trial_until": _iso_or_none(trial_until),
        }

    if exp_dt or grace_dt or trial_dt:
        return {
            "active": False,
            "state": "expired",
            "reason": "expired",
            "plan_code": plan_code,
            "expires_at": _iso_or_none(expires_at),
            "grace_until": _iso_or_none(grace_until),
            "trial_until": _iso_or_none(trial_until),
        }

    return {
        "active": False,
        "state": "none",
        "reason": "no_subscription",
        "plan_code": None,
        "expires_at": None,
        "grace_until": None,
        "trial_until": None,
    }


def _try_fetch_latest_row(
    *,
    account_id: str,
    table_name: str,
    id_col: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Returns (row, safe_error_string).
    """
    try:
        db = supabase()
        res = (
            db.table(table_name)
            .select("*")
            .eq(id_col, account_id)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        return (rows[0] if rows else None), None
    except Exception as e:
        return None, _sanitize_err(e)


def get_subscription_status(account_id: str) -> Dict[str, Any]:
    """
    Compatibility reader across schemas.

    Tries tables:
      - SUBSCRIPTIONS_TABLE env var (if set)
      - user_subscriptions
      - subscriptions

    Tries id columns:
      - account_id
      - user_id

    Returns:
      {
        account_id: str,
        active: bool,
        state: "active"|"trial"|"grace"|"expired"|"none",
        plan_code: str|null,
        expires_at: str|null,
        grace_until: str|null,
        trial_until: str|null,
        reason: str,
        debug_source: { table, id_col, error? }   # safe
      }
    """
    account_id = (account_id or "").strip()
    if not account_id:
        return {
            "account_id": "",
            "active": False,
            "state": "none",
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
            "trial_until": None,
            "reason": "no_account_id",
            "debug_source": {"table": None, "id_col": None},
        }

    env_table = (os.getenv("SUBSCRIPTIONS_TABLE", "") or "").strip()
    tables: List[str] = [t for t in [env_table, "user_subscriptions", "subscriptions"] if t]
    id_cols = ["account_id", "user_id"]

    latest_row: Optional[Dict[str, Any]] = None
    used_table: Optional[str] = None
    used_id_col: Optional[str] = None
    last_error: Optional[str] = None

    for t in tables:
        for c in id_cols:
            row, err = _try_fetch_latest_row(account_id=account_id, table_name=t, id_col=c)
            if err:
                last_error = err
                continue
            if row:
                latest_row = row
                used_table = t
                used_id_col = c
                break
        if latest_row:
            break

    if not latest_row:
        return {
            "account_id": account_id,
            "active": False,
            "state": "none",
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
            "trial_until": None,
            "reason": "no_subscription" if not last_error else "db_error",
            "debug_source": {"table": None, "id_col": None, "error": last_error},
        }

    plan_code = latest_row.get("plan_code") or latest_row.get("plan") or None
    status = latest_row.get("status") or None
    expires_at = latest_row.get("expires_at") or latest_row.get("expires") or None
    grace_until = latest_row.get("grace_until") or latest_row.get("grace") or None
    trial_until = latest_row.get("trial_until") or latest_row.get("trial") or None

    computed = _compute_state(
        now=_now_utc(),
        plan_code=plan_code,
        status=status,
        expires_at=expires_at,
        grace_until=grace_until,
        trial_until=trial_until,
    )

    return {
        "account_id": account_id,
        **computed,
        "debug_source": {"table": used_table, "id_col": used_id_col},
    }
