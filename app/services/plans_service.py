# app/services/plans_service.py
from __future__ import annotations

from typing import Any, Dict, List, Optional
from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def list_plans() -> List[Dict[str, Any]]:
    """
    Reads plans from Supabase table 'plans' if it exists.
    Returns [] safely if table is missing or query fails.
    """
    try:
        res = _sb().table("plans").select("plan_code,name,duration_days,active,created_at").order("duration_days").execute()
        return (getattr(res, "data", None) or []) or []
    except Exception:
        return []


def get_plan(plan_code: str) -> Optional[Dict[str, Any]]:
    plan_code = (plan_code or "").strip()
    if not plan_code:
        return None
    try:
        res = _sb().table("plans").select("plan_code,name,duration_days,active,created_at").eq("plan_code", plan_code).limit(1).execute()
        rows = (getattr(res, "data", None) or []) or []
        return rows[0] if rows else None
    except Exception:
        return None
