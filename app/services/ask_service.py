# app/services/ask_service.py
from __future__ import annotations

"""
ASK SERVICE (CANONICAL)

- Uses ONLY canonical identity: accounts.account_id
- If older clients send accounts.id, it translates to accounts.account_id and exposes it in debug

This service is called by routes/ask.py (web + legacy channels).
"""

import uuid
from typing import Any, Dict

from app.core.supabase_client import supabase
from app.core import config as CFG
from app.services.credits_service import check_credit_balance
from app.services.qa_cache_service import answer_from_cache, increment_cache_use
from app.services.ai_service import call_ai


def _sb():
    return supabase() if callable(supabase) else supabase


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


def resolve_canonical_account_id(raw_account_id: str) -> Dict[str, Any]:
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

    # Preferred path: client already sent canonical accounts.account_id
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

    # Legacy path: client sent accounts.id
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

        # Repair: if account_id is missing, set account_id = id
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


def ask_guarded(body: Dict[str, Any]) -> Dict[str, Any]:
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

    translation_debug: Dict[str, Any] = {}
    if resolved.get("translated_from_id"):
        translation_debug = {
            "note": "legacy accounts.id was supplied; translated to canonical accounts.account_id",
            "translated_from_id": resolved.get("translated_from_id"),
        }

    # --------------------------
    # Bypass enforcement (single authority)
    # --------------------------
    bypass_requested = bool(body.get("__bypass"))
    if bypass_requested and not CFG.ALLOW_SUBSCRIPTION_BYPASS:
        return {
            "ok": False,
            "error": "bypass_disabled",
            "root_cause": "__bypass was requested but ALLOW_SUBSCRIPTION_BYPASS is False",
            "fix": "Disable bypass request (remove BYPASS token headers) or explicitly enable DEV_BYPASS_SUBSCRIPTION=1 (dev only).",
            "debug": {
                **translation_debug,
                "bypass_requested": True,
                "ALLOW_SUBSCRIPTION_BYPASS": CFG.ALLOW_SUBSCRIPTION_BYPASS,
                "DEV_BYPASS_SUBSCRIPTION": getattr(CFG, "DEV_BYPASS_SUBSCRIPTION", None),
                "BYPASS_TOKEN_present": bool(getattr(CFG, "BYPASS_TOKEN", "")),
                "DEV_BYPASS_TOKEN_present": bool(getattr(CFG, "DEV_BYPASS_TOKEN", "")),
            },
        }

    # Cache shortcut
    cached = answer_from_cache(question, lang=(body.get("lang") or "en"))
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
            "debug": {**translation_debug, "bypass": bypass_requested},
        }

    # Credits / subscription gating (skip only if bypass is allowed AND requested)
    if not bypass_requested:
        bal = check_credit_balance(account_id)
        if not bal.get("ok"):
            return {
                "ok": False,
                "error": "credit_check_failed",
                "root_cause": bal.get("root_cause") or bal.get("error"),
                "fix": bal.get("fix") or "Fix credits table/RLS.",
                "details": bal.get("details") or {"account_id": account_id},
                "debug": {**translation_debug},
            }

        balance_val = int(bal.get("balance") or 0)
        if balance_val <= 0:
            return {
                "ok": False,
                "error": "insufficient_credits",
                "root_cause": "ai_credits_balance_zero",
                "fix": "Top up credits or subscribe to a plan that includes AI credits.",
                "details": {"account_id": account_id, "balance": balance_val},
                "debug": {**translation_debug},
            }

    # AI call
    try:
        ai = call_ai(question=question, lang=(body.get("lang") or "en"), channel=(body.get("channel") or "web"))
    except Exception as e:
        return {
            "ok": False,
            "error": "ai_call_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check AI provider keys, network access, and ai_service configuration.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug, "bypass": bypass_requested},
        }

    if not isinstance(ai, dict) or not ai.get("ok"):
        return {
            "ok": False,
            "error": "ai_failed",
            "root_cause": (ai or {}).get("root_cause") or (ai or {}).get("error") or "unknown_ai_failure",
            "fix": (ai or {}).get("fix") or "Inspect ai_service logs.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug, "bypass": bypass_requested},
        }

    return {
        "ok": True,
        "answer": ai.get("answer"),
        "from_cache": False,
        "account_id": account_id,
        "debug": {**translation_debug, "bypass": bypass_requested},
    }
