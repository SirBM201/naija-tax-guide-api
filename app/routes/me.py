# app/routes/me.py
from __future__ import annotations

"""/me endpoint (CANONICAL)

Returns:
  - account_id == accounts.account_id

Supports schema drift:
  - accounts.auth_user_id or accounts.supabase_user_id

Auto-repair:
  - if accounts.account_id is NULL, set it to accounts.id

"""

from flask import Blueprint, jsonify

from app.core.supabase_client import supabase
from app.services.auth_service import get_current_user

bp = Blueprint("me", __name__)


def _sb():
    return supabase() if callable(supabase) else supabase


def _clip(s: str, n: int = 240) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def _repair_account_id(row: dict) -> dict:
    row_id = str(row.get("id") or "").strip()
    account_id = str(row.get("account_id") or "").strip()
    if account_id:
        return {"ok": True, "account_id": account_id}
    if not row_id:
        return {
            "ok": False,
            "error": "account_id_missing",
            "root_cause": "accounts row missing both id and account_id",
            "fix": "Ensure accounts.id has default uuid and accounts.account_id exists.",
        }
    try:
        _sb().table("accounts").update({"account_id": row_id}).eq("id", row_id).execute()
        return {"ok": True, "account_id": row_id, "repaired": True}
    except Exception as e:
        return {
            "ok": False,
            "error": "account_id_repair_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Run SQL: update accounts set account_id=id where account_id is null; UNIQUE index on account_id.",
            "details": {"row_id": row_id},
        }


@bp.get("/me")
def me():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    sb = _sb()
    uid = str(user.get("id") or "").strip()
    if not uid:
        return jsonify({
            "ok": False,
            "error": "unauthorized",
            "root_cause": "auth user id missing",
            "fix": "Ensure auth_service returns a valid user object with id.",
        }), 401

    # Pick whichever column exists
    key_col = "auth_user_id" if _has_column("accounts", "auth_user_id") else ("supabase_user_id" if _has_column("accounts", "supabase_user_id") else "")
    if not key_col:
        return jsonify({
            "ok": False,
            "error": "schema_invalid",
            "root_cause": "accounts.auth_user_id / accounts.supabase_user_id missing",
            "fix": "Add accounts.auth_user_id (preferred) or accounts.supabase_user_id to map Supabase Auth users.",
        }), 500

    # Lookup
    try:
        res = sb.table("accounts").select("id,account_id").eq(key_col, uid).limit(1).execute()
        row = (getattr(res, "data", None) or [None])[0] or None
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": "accounts_lookup_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check accounts table permissions/RLS.",
        }), 500

    if row:
        rep = _repair_account_id(row)
        if not rep.get("ok"):
            return jsonify(rep), 500
        return jsonify({"ok": True, "account_id": rep["account_id"], "user_id": uid, "repaired": bool(rep.get("repaired"))}), 200

    # Create if missing
    payload = {key_col: uid, "provider": "web"}
    try:
        created = sb.table("accounts").insert(payload).select("id,account_id").execute()
        row = (getattr(created, "data", None) or [None])[0] or None
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": "account_create_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check RLS for accounts insert and required columns.",
        }), 500

    if not row:
        return jsonify({
            "ok": False,
            "error": "account_create_failed",
            "root_cause": "insert returned no row",
            "fix": "Ensure Supabase returns representation rows for inserts.",
        }), 500

    rep = _repair_account_id(row)
    if not rep.get("ok"):
        return jsonify(rep), 500

    return jsonify({"ok": True, "account_id": rep["account_id"], "user_id": uid, "created": True, "repaired": bool(rep.get("repaired"))}), 200
