# app/services/accounts_web_link_service.py
from __future__ import annotations

"""accounts_web_link_service (CANONICAL)

This file links a Supabase auth user (supabase_user_id) to an app account.

✅ Canonical identity:
  - app account identity is accounts.account_id
  - accounts.id is ONLY row PK, never used as identity outside accounts table

What this function returns:
  - { ok: True, account_id: <accounts.account_id> }

It also auto-repairs rows where account_id is NULL by setting account_id = id.

Failure exposers:
  - returns error + root_cause + fix (+ details)

"""

from typing import Any, Dict

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def _clip(s: str, n: int = 220) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


def link_web_user_to_account(supabase_user_id: str, account_id: str) -> Dict[str, Any]:
    """Link a Supabase auth user to an existing app account.

    Inputs:
      - supabase_user_id: UUID from Supabase Auth
      - account_id: MUST be canonical accounts.account_id

    Note: For MVP, we store this mapping on accounts.auth_user_id (if present).
    """

    supabase_user_id = (supabase_user_id or "").strip()
    account_id = (account_id or "").strip()

    if not supabase_user_id or not account_id:
        return {
            "ok": False,
            "error": "missing_inputs",
            "root_cause": "supabase_user_id or account_id empty",
            "fix": "Provide supabase_user_id and canonical account_id.",
        }

    # Ensure accounts table supports auth_user_id
    if not _has_column("accounts", "auth_user_id"):
        return {
            "ok": False,
            "error": "schema_invalid",
            "root_cause": "accounts.auth_user_id column is missing",
            "fix": "Add accounts.auth_user_id (uuid/text) or implement a separate mapping table.",
        }

    # Update by canonical account_id
    try:
        res = (
            _sb()
            .table("accounts")
            .update({"auth_user_id": supabase_user_id})
            .eq("account_id", account_id)
            .select("id,account_id,auth_user_id")
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
    except Exception as e:
        return {
            "ok": False,
            "error": "link_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check accounts table RLS permissions for update.",
            "details": {"account_id": account_id},
        }

    if not rows:
        return {
            "ok": False,
            "error": "account_not_found",
            "root_cause": "no accounts row matched by account_id",
            "fix": "Ensure the account exists and account_id is canonical accounts.account_id.",
            "details": {"account_id": account_id},
        }

    # auto-repair account_id if missing (should not happen if schema is correct)
    row = rows[0] or {}
    canonical = str(row.get("account_id") or "").strip()
    row_id = str(row.get("id") or "").strip()

    if not canonical and row_id:
        try:
            _sb().table("accounts").update({"account_id": row_id}).eq("id", row_id).execute()
            canonical = row_id
        except Exception as e:
            return {
                "ok": False,
                "error": "account_id_repair_failed",
                "root_cause": f"accounts.account_id was NULL and repair failed: {type(e).__name__}: {_clip(str(e))}",
                "fix": "Run SQL: update accounts set account_id=id where account_id is null; add UNIQUE index; fix FKs.",
                "details": {"row_id": row_id},
            }

    if not canonical:
        return {
            "ok": False,
            "error": "account_id_missing",
            "root_cause": "linked row exists but canonical account_id is empty",
            "fix": "Ensure accounts.account_id exists and is populated.",
            "details": {"row": row},
        }

    return {"ok": True, "account_id": canonical}
