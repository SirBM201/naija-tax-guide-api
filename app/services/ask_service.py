# app/services/ask_service.py
from __future__ import annotations

"""
ASK SERVICE (CANONICAL)

Goal:
- Use ONLY canonical identity: accounts.account_id
- Never silently treat accounts.id as the app identity
- If older clients send accounts.id, we TRANSLATE it to accounts.account_id (and expose it)
- Provide strong failure exposers: error + root_cause + fix (+ optional debug)

This service is called by:
- routes/ask.py (web + legacy channels)

Key invariants:
- Any downstream service that touches subscriptions/credits/tokens must receive canonical account_id.

"""

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from app.core.supabase_client import supabase
from app.services.credits_service import check_credit_balance
from app.services.qa_cache_service import answer_from_cache, increment_cache_use
from app.services.ai_service import call_ai


# -----------------------------
# Helpers
# -----------------------------

def _sb():
    return supabase() if callable(supabase) else supabase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _clip(s: str, n: int = 240) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[:n] + "…"


def _is_uuid(v: str) -> bool:
    try:
        uuid.UUID(str(v))
        return True
    except Exception:
        return False


def _has_column(table: str, col: str) -> bool:
    try:
        _sb().table(table).select(col).limit(1).execute()
        return True
    except Exception:
        return False


# -----------------------------
# Canonical account id resolution
# -----------------------------

def resolve_canonical_account_id(raw_account_id: str) -> Dict[str, Any]:
    """Resolve incoming identifier to canonical accounts.account_id.

    Accepts:
      - canonical accounts.account_id
      - legacy accounts.id (translated)

    Returns:
      { ok: True, account_id: <canonical>, translated_from_id?: <legacy-id> }
      { ok: False, error, root_cause, fix }
    """
    v = (raw_account_id or "").strip()
    if not v:
        return {
            "ok": False,
            "error": "account_required",
            "root_cause": "missing_account_id",
            "fix": "Provide account_id or authenticate via web cookie/bearer so the server can derive it.",
        }

    if not _is_uuid(v):
        return {
            "ok": False,
            "error": "account_invalid",
            "root_cause": "account_id_not_uuid",
            "fix": "Send a valid UUID for account_id.",
            "details": {"account_id": v},
        }

    # 1) Try canonical: accounts.account_id = v
    if _has_column("accounts", "account_id"):
        try:
            q = _sb().table("accounts").select("id,account_id").eq("account_id", v).limit(1).execute()
            rows = getattr(q, "data", None) or []
            if rows:
                return {"ok": True, "account_id": str(rows[0].get("account_id") or v)}
        except Exception as e:
            return {
                "ok": False,
                "error": "account_lookup_failed",
                "root_cause": f"accounts lookup by account_id failed: {type(e).__name__}: {_clip(str(e))}",
                "fix": "Check Supabase connectivity/RLS for accounts table.",
            }

    # 2) Try legacy: accounts.id = v, translate to account_id
    try:
        q = _sb().table("accounts").select("id,account_id").eq("id", v).limit(1).execute()
        rows = getattr(q, "data", None) or []
        if not rows:
            return {
                "ok": False,
                "error": "account_not_found",
                "root_cause": "no accounts row matches account_id nor id",
                "fix": "Ensure the account exists. If using web auth, verify OTP first to create/resolve account.",
                "details": {"provided": v},
            }

        row = rows[0] or {}
        canonical = str(row.get("account_id") or "").strip()
        row_id = str(row.get("id") or "").strip()

        # auto-repair missing account_id
        if not canonical and row_id:
            try:
                _sb().table("accounts").update({"account_id": row_id}).eq("id", row_id).execute()
                canonical = row_id
            except Exception as e:
                return {
                    "ok": False,
                    "error": "account_id_repair_failed",
                    "root_cause": f"accounts.account_id was NULL and repair failed: {type(e).__name__}: {_clip(str(e))}",
                    "fix": "Run SQL: update accounts set account_id=id where account_id is null; then UNIQUE index on account_id.",
                    "details": {"row_id": row_id},
                }

        if not canonical:
            return {
                "ok": False,
                "error": "account_id_missing",
                "root_cause": "accounts row exists but account_id is empty",
                "fix": "Ensure accounts.account_id exists and is populated.",
                "details": {"row_id": row_id},
            }

        return {"ok": True, "account_id": canonical, "translated_from_id": v}

    except Exception as e:
        return {
            "ok": False,
            "error": "account_lookup_failed",
            "root_cause": f"accounts lookup by id failed: {type(e).__name__}: {_clip(str(e))}",
            "fix": "Check Supabase connectivity/RLS for accounts table.",
        }


# -----------------------------
# Main guarded ask
# -----------------------------

def ask_guarded(body: Dict[str, Any]) -> Dict[str, Any]:
    """Guarded ask endpoint.

    Expected inputs:
      - question (required)
      - account_id (preferred) OR web cookie/bearer sets body['account_id'] in route
      - __bypass optional (dev)

    Output:
      { ok: True, answer, from_cache, ... }
      { ok: False, error, root_cause, fix, ... }
    """

    question = (body.get("question") or "").strip()
    if not question:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "missing_question",
            "fix": "Provide a non-empty question string.",
        }

    raw_account_id = (body.get("account_id") or "").strip()
    resolved = resolve_canonical_account_id(raw_account_id)
    if not resolved.get("ok"):
        return resolved

    account_id = str(resolved["account_id"]).strip()

    # Expose translation if legacy id was supplied
    translation_debug = {}
    if resolved.get("translated_from_id"):
        translation_debug = {
            "note": "legacy accounts.id was supplied; translated to canonical accounts.account_id",
            "translated_from_id": resolved.get("translated_from_id"),
        }

    # DEV bypass: allows asking even without subscription/credits
    bypass = bool(body.get("__bypass"))
    if bypass and not _truthy(os.getenv("ALLOW_DEV_BYPASS", "1")):
        return {
            "ok": False,
            "error": "bypass_disabled",
            "root_cause": "__bypass provided but ALLOW_DEV_BYPASS=0",
            "fix": "Remove bypass headers or set ALLOW_DEV_BYPASS=1 in backend env.",
        }

    # 1) Try cache
    try:
        cached = answer_from_cache(question)
    except Exception as e:
        cached = None
        cache_err = {
            "cache_error": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check qa_cache table/RPC and indexes.",
        }

    if cached:
        try:
            increment_cache_use(cached.get("id"))
        except Exception:
            pass

        return {
            "ok": True,
            "answer": cached.get("answer"),
            "from_cache": True,
            "account_id": account_id,
            "debug": {**translation_debug},
        }

    # 2) Credits check (unless bypass)
    if not bypass:
        bal = check_credit_balance(account_id)
        if not bal.get("ok"):
            # make sure credit service errors are visible
            return {
                "ok": False,
                "error": "credit_check_failed",
                "root_cause": bal.get("root_cause") or bal.get("error"),
                "fix": bal.get("fix") or "Fix credits table/RPC or RLS.",
                "details": bal.get("details") or {"account_id": account_id},
                "debug": {**translation_debug},
            }

        if bal.get("credits", 0) <= 0:
            return {
                "ok": False,
                "error": "insufficient_credits",
                "root_cause": "ai_credits_balance_zero",
                "fix": "Top up credits or subscribe to a plan that includes AI credits.",
                "details": {"account_id": account_id, "credits": bal.get("credits")},
                "debug": {**translation_debug},
            }

    # 3) Call AI
    try:
        ai = call_ai(question=question, lang=(body.get("lang") or "en"), channel=(body.get("channel") or "web"))
    except Exception as e:
        return {
            "ok": False,
            "error": "ai_call_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check AI provider keys, network access, and ai_service configuration.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug},
        }

    if not isinstance(ai, dict) or not ai.get("ok"):
        return {
            "ok": False,
            "error": "ai_failed",
            "root_cause": (ai or {}).get("root_cause") or (ai or {}).get("error") or "unknown_ai_failure",
            "fix": (ai or {}).get("fix") or "Inspect ai_service logs.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug},
        }

    return {
        "ok": True,
        "answer": ai.get("answer"),
        "from_cache": False,
        "account_id": account_id,
        "debug": {**translation_debug},
    }
