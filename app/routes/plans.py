# app/routes/plans.py
from flask import Blueprint, jsonify

from ..core.supabase_client import supabase

bp = Blueprint("plans", __name__)


@bp.get("/plans")
def list_plans():
    """
    Returns active plans for frontend pricing page.
    """
    db = supabase()
    res = db.table("plans").select("plan_code,name,duration_days,active,created_at").eq("active", True).execute()
    return jsonify({"ok": True, "plans": res.data or []}), 200
