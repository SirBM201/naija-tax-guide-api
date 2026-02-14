# app/core/auth.py
from __future__ import annotations

import os
import hashlib
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple

from flask import g, request, jsonify

from app.core.supabase_client import supabase


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# -----------------------------
# ENV (your real schema)
# -----------------------------
WEB_TOKEN_TABLE = (os.getenv("WEB_TOKEN_TABLE", "web_sessions") or "web_sessions").strip()

WEB_TOKEN_COL_TOKEN = (os.getenv("WEB_TOKEN_COL_TOKEN", "token_hash") or "token_hash").strip()
WEB_TOKEN_COL_ACCOUNT_ID = (os.getenv("WEB_TOKEN_COL_ACCOUNT_ID", "account_id") or "account_id").strip()
WEB_TOKEN_COL_EXPIRES_AT = (os.getenv("WEB_TOKEN_COL_EXPIRES_AT", "expires_at") or "expires_at").strip()
WEB_TOKEN_COL_REVOKED_AT = (os.getenv("WEB_TOKEN_COL_REVOKED_AT", "revoked_at") or "revoked_at").strip()

WEB_TOKEN_PEPPER = (os.getenv("WEB_TOKEN_PEPPER", "") or "").strip()


# -----------------------------
# Token helpers
# -----------------------------
def _bearer_token() -> str:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth:
        return ""
    # Accept: "Bearer xxx"
    parts = auth.split(" ", 1)
    if len(parts) != 2:
        return ""
    if parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def _hash_token(token: str) -> str:
    """
    token_hash = sha256(f"{pepper}:{token}")
    """
    if not WEB_TOKEN_PEPPER:
        # If pepper not set, we refuse (otherwise your tokens become insecure/unstable).
        raise RuntimeError("WEB_TOKEN_PEPPER is not set")
    raw = f"{WEB_TOKEN_PEPPER}:{token}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _get_token_row(token: str) -> Optional[Dict[str, Any]]:
    """
    Finds token in WEB_TOKEN_TABLE by hashed token value.
    Expects schema: web_sessions(token_hash, account_id, expires_at, revoked_at)
    """
    if not token:
        return None

    token_hash = _hash_token(token)

    try:
        res = (
            supabase.table(WEB_TOKEN_TABLE)
            .select(f"{WEB_TOKEN_COL_ACCOUNT_ID}, {WEB_TOKEN_COL_EXPIRES_AT}, {WEB_TOKEN_COL_REVOKED_AT}, {WEB_TOKEN_COL_TOKEN}")
            .eq(WEB_TOKEN_COL_TOKEN, token_hash)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        return rows[0] if rows else None
    except Exception:
        return None


def _is_token_valid(row: Dict[str, Any]) -> bool:
    if not row:
        return False

    if row.get(WEB_TOKEN_COL_REVOKED_AT):
        return False

    exp = row.get(WEB_TOKEN_COL_EXPIRES_AT)
    if not exp:
        return False

    # exp is ISO string in Supabase
    try:
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
    except Exception:
        return False

    return exp_dt > _now_utc()


# -----------------------------
# Subscription + Credits loaders
# -----------------------------
def _load_subscription(account_id: str) -> Dict[str, Any]:
    """
    Minimal subscription status from your user_subscriptions table.
    If you already have a richer helper in subscriptions_service.py, you can swap this later.
    """
    try:
        res = (
            supabase.table("user_subscriptions")
            .select("account_id, plan_code, expires_at, grace_until, active, created_at, updated_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        if not rows:
            return {"active": False, "plan_code": None, "expires_at": None, "state": "none"}

        r = rows[0]
        expires_at = r.get("expires_at")
        grace_until = r.get("grace_until")
        active = bool(r.get("active"))

        state = "active" if active else "expired"
        return {
            "active": active,
            "plan_code": r.get("plan_code"),
            "expires_at": expires_at,
            "grace_until": grace_until,
            "state": state,
        }
    except Exception:
        return {"active": False, "plan_code": None, "expires_at": None, "state": "none"}


def _load_credits(account_id: str) -> Dict[str, Any]:
    """
    Your schema:
      public.ai_credit_balances(account_id uuid, balance int4, updated_at timestamptz)
    """
    try:
        res = (
            supabase.table("ai_credit_balances")
            .select("account_id, balance, updated_at")
            .eq("account_id", account_id)
            .limit(1)
            .execute()
        )
        rows = (res.data or []) if hasattr(res, "data") else []
        if not rows:
            return {"balance": 0}

        bal = rows[0].get("balance") or 0
        return {"balance": int(bal)}
    except Exception:
        return {"balance": 0}


# -----------------------------
# Decorator (works with or without parentheses)
# -----------------------------
def require_auth_plus(fn: Optional[Callable] = None) -> Callable:
    """
    You can use:
      @require_auth_plus
    OR:
      @require_auth_plus()

    Sets:
      g.account_id
      g.auth_token
      g.token_row
      g.subscription
      g.credits
    """

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            token = _bearer_token()
            if not token:
                return jsonify({"ok": False, "error": "Unauthorized"}), 401

            row = _get_token_row(token)
            if not row or not _is_token_valid(row):
                return jsonify({"ok": False, "error": "Unauthorized"}), 401

            account_id = (row.get(WEB_TOKEN_COL_ACCOUNT_ID) or "").strip()
            if not account_id:
                return jsonify({"ok": False, "error": "Unauthorized"}), 401

            g.account_id = account_id
            g.auth_token = token
            g.token_row = {
                "expires_at": row.get(WEB_TOKEN_COL_EXPIRES_AT),
                "revoked_at": row.get(WEB_TOKEN_COL_REVOKED_AT),
            }

            g.subscription = _load_subscription(account_id)
            g.credits = _load_credits(account_id)

            return view_func(*args, **kwargs)

        return wrapper

    # If used as @require_auth_plus (no parentheses)
    if callable(fn):
        return decorator(fn)

    # If used as @require_auth_plus()
    return decorator
