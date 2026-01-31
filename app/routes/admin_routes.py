# app/routes/admin_routes.py
import os
import logging
from flask import Blueprint, request, jsonify

from app.core.supabase_client import supabase

log = logging.getLogger(__name__)
bp = Blueprint("admin", __name__)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "").strip()


def require_admin():
    if not ADMIN_API_KEY:
        return False
    got = request.headers.get("x-admin-key", "").strip()
    return got == ADMIN_API_KEY


@bp.get("/admin/summary")
def admin_summary():
    if not require_admin():
        return jsonify(ok=False, message="Unauthorized"), 401

    # quick counts (simple + fast)
    try:
        subs = supabase().table("user_subscriptions").select("wa_phone,status,plan,expires_at", count="exact").execute()
        accounts = supabase().table("accounts").select("id,provider", count="exact").execute()

        return jsonify(ok=True, data={
            "subscriptions_count": subs.count or 0,
            "accounts_count": accounts.count or 0,
        }), 200
    except Exception as e:
        log.exception("admin_summary failed")
        return jsonify(ok=False, message="Server error", detail=str(e)), 500


@bp.get("/admin/subscriptions")
def admin_subscriptions():
    if not require_admin():
        return jsonify(ok=False, message="Unauthorized"), 401

    try:
        r = (
            supabase()
            .table("user_subscriptions")
            .select("wa_phone,plan,status,expires_at,paystack_reference,updated_at")
            .order("updated_at", desc=True)
            .limit(200)
            .execute()
        )
        return jsonify(ok=True, data=r.data or []), 200
    except Exception as e:
        log.exception("admin_subscriptions failed")
        return jsonify(ok=False, message="Server error", detail=str(e)), 500


@bp.get("/admin/accounts")
def admin_accounts():
    if not require_admin():
        return jsonify(ok=False, message="Unauthorized"), 401

    try:
        r = (
            supabase()
            .table("accounts")
            .select("id,provider,provider_user_id,phone_e164,created_at")
            .order("created_at", desc=True)
            .limit(200)
            .execute()
        )
        return jsonify(ok=True, data=r.data or []), 200
    except Exception as e:
        log.exception("admin_accounts failed")
        return jsonify(ok=False, message="Server error", detail=str(e)), 500
