# app/services/plans_service.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.supabase_client import supabase


# Fallback defaults (used if table doesn't exist yet or returns nothing)
DEFAULT_PLANS: List[Dict[str, Any]] = [
    {"plan_code": "monthly", "name": "Monthly", "duration_days": 30, "active": True},
    {"plan_code": "quarterly", "name": "Quarterly", "duration_days": 90, "active": True},
    {"plan_code": "yearly", "name": "Yearly", "duration_days": 365, "active": True},
    {"plan_code": "trial", "name": "Trial", "duration_days": 7, "active": True},
]


def _sb():
    # supabase can be client or factory depending on your setup
    return supabase() if callable(supabase) else supabase


def list_plans(active_only: bool = True) -> List[Dict[str, Any]]:
    """
    Try to read plans from Supabase table 'plans'.
    If table doesn't exist yet, return DEFAULT_PLANS so the API still works.
    """
    try:
        q = _sb().table("plans").select("plan_code,name,duration_days,active,created_at")
        if active_only:
            q = q.eq("active", True)
        res = q.order("duration_days", desc=False).execute()
        rows = (res.data or []) if hasattr(res, "data") else []
        if rows:
            return rows
        return [p for p in DEFAULT_PLANS if (p.get("active") is True or not active_only)]
    except Exception:
        return [p for p in DEFAULT_PLANS if (p.get("active") is True or not active_only)]


def get_plan(plan_code: str) -> Optional[Dict[str, Any]]:
    """
    Fetch a single plan by code from Supabase 'plans' table.
    Falls back to DEFAULT_PLANS if DB is not ready.
    """
    code = (plan_code or "").strip().lower()
    if not code:
        return None

    try:
        res = (
            _sb()
            .table("plans")
            .select("plan_code,name,duration_days,active,created_at")
            .eq("plan_code", code)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        if rows:
            return rows[0]
    except Exception:
        pass

    for p in DEFAULT_PLANS:
        if (p.get("plan_code") or "").lower() == code:
            return p
    return None
