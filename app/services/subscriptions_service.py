# app/services/subscriptions_service.py
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, List

from ..core.supabase_client import supabase
from ..services.subscription_status_service import get_subscription_status


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize_err(e: Exception) -> str:
    s = str(e) or e.__class__.__name__
    s = s.replace("\n", " ").strip()
    return s[:280]


def _insert_try(
    *,
    table_name: str,
    id_col: str,
    plan_col: str,
    account_id: str,
    plan_code: str,
    status: str,
    expires_at_iso: Optional[str],
    grace_until_iso: Optional[str],
    trial_until_iso: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        db = supabase()
        payload: Dict[str, Any] = {
            id_col: account_id,
            plan_col: plan_code,
            "status": status,
        }
        if expires_at_iso:
            payload["expires_at"] = expires_at_iso
        if grace_until_iso:
            payload["grace_until"] = grace_until_iso
        if trial_until_iso:
            payload["trial_until"] = trial_until_iso

        res = db.table(table_name).insert(payload).execute()
        rows = getattr(res, "data", None) or []
        return (rows[0] if rows else payload), None
    except Exception as e:
        return None, _sanitize_err(e)


def activate_subscription_now(
    *,
    user_id: str,
    plan_code: str = "manual",
    expires_at_iso: Optional[str] = None,
    status: str = "active",
    grace_until_iso: Optional[str] = None,
    trial_until_iso: Optional[str] = None,
) -> Dict[str, Any]:
    """
    ADMIN helper:
    Inserts a subscription row in a schema-compatible way.

    Tries:
      tables: SUBSCRIPTIONS_TABLE env (or 'subscriptions')
      id_col: account_id then user_id
      plan_col: plan_code then plan
    """
    account_id = (user_id or "").strip()
    if not account_id:
        return {"ok": False, "error": "missing_account_id"}

    table = (os.getenv("SUBSCRIPTIONS_TABLE", "") or "").strip() or "subscriptions"

    id_cols: List[str] = ["account_id", "user_id"]
    plan_cols: List[str] = ["plan_code", "plan"]

    last_error: Optional[str] = None
    used_id_col: Optional[str] = None
    used_plan_col: Optional[str] = None
    inserted: Optional[Dict[str, Any]] = None

    for id_col in id_cols:
        for plan_col in plan_cols:
            row, err = _insert_try(
                table_name=table,
                id_col=id_col,
                plan_col=plan_col,
                account_id=account_id,
                plan_code=plan_code,
                status=status,
                expires_at_iso=expires_at_iso,
                grace_until_iso=grace_until_iso,
                trial_until_iso=trial_until_iso,
            )
            if err:
                last_error = err
                continue
            inserted = row
            used_id_col = id_col
            used_plan_col = plan_col
            break
        if inserted:
            break

    if not inserted:
        return {
            "ok": False,
            "error": "db_insert_failed",
            "message": last_error or "insert failed",
            "debug_source": {"table": table, "id_col": None, "plan_col": None},
        }

    # Return computed status after insert (uses your compatibility reader)
    computed = get_subscription_status(account_id)

    return {
        "ok": True,
        "account_id": account_id,
        "inserted": inserted,
        "computed_status": computed,
        "debug_source": {"table": table, "id_col": used_id_col, "plan_col": used_plan_col},
        "ts": _now_utc().isoformat(),
    }
