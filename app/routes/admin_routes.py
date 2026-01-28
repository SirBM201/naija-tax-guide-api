import os
from flask import Blueprint, request, jsonify, make_response
from app.routes.admin_guard import is_admin_authed, admin_expected_key, COOKIE_NAME
from app.db.supabase_client import supabase

bp = Blueprint("admin", __name__)

def _deny():
    return jsonify(ok=False, message="admin unauthorized"), 401

@bp.post("/admin/login")
def admin_login():
    body = request.get_json(silent=True) or {}
    provided = (body.get("key") or "").strip()
    expected = admin_expected_key()
    if not expected:
        return jsonify(ok=False, message="ADMIN_ACCESS_KEY not set"), 500
    if provided != expected:
        return jsonify(ok=False, message="invalid key"), 401

    resp = make_response(jsonify(ok=True))
    resp.set_cookie(COOKIE_NAME, expected, httponly=True, samesite="Lax", secure=True)
    return resp

@bp.post("/admin/logout")
def admin_logout():
    resp = make_response(jsonify(ok=True))
    resp.delete_cookie(COOKIE_NAME)
    return resp

@bp.get("/admin/summary")
def admin_summary():
    if not is_admin_authed():
        return _deny()

    accts = supabase().table("accounts").select("acct_id", count="exact").execute()
    subs = supabase().table("subscriptions").select("acct_id", count="exact").execute()
    ids  = supabase().table("account_identities").select("acct_id", count="exact").execute()

    return jsonify(
        ok=True,
        accounts=getattr(accts, "count", None),
        subscriptions=getattr(subs, "count", None),
        identities=getattr(ids, "count", None),
    )

@bp.get("/admin/accounts")
def admin_accounts():
    if not is_admin_authed():
        return _deny()
    r = supabase().table("accounts").select("*").order("created_at", desc=True).limit(200).execute()
    return jsonify(ok=True, rows=getattr(r, "data", []) or [])

@bp.get("/admin/subscriptions")
def admin_subscriptions():
    if not is_admin_authed():
        return _deny()
    r = supabase().table("subscriptions").select("*").order("expires_at", desc=True).limit(200).execute()
    return jsonify(ok=True, rows=getattr(r, "data", []) or [])
