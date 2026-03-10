from __future__ import annotations

"""
ASK SERVICE (CANONICAL)

- Uses ONLY canonical identity: accounts.account_id
- If older clients send accounts.id, it translates to accounts.account_id and exposes it in debug
- Enforces:
  - active subscription injected by ask route
  - daily plan limit
  - credit balance
- Charges:
  - cached answer -> counts toward daily limit, does NOT consume credits
  - fresh AI answer -> counts toward daily limit AND consumes 1 credit after success
- Writes:
  - qa_history
  - qa_embeddings (when cache_id exists and embeddings are configured)
"""

import os
import uuid
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase
from app.services.credits_service import (
    check_credit_balance,
    consume_credits,
    enforce_daily_limit,
    get_plan_limits,
    increment_daily_usage,
)
from app.services.qa_cache_service import (
    answer_from_cache,
    increment_cache_use,
    upsert_ai_answer_to_cache_best_effort,
    derive_canonical_key,
    normalize_question_for_cache,
)
from app.services.ai_service import call_ai
from app.services.semantic_runtime_service import semantic_write_runtime


def _sb():
    return supabase() if callable(supabase) else supabase


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


def _resolve_plan_context(body: Dict[str, Any]) -> Dict[str, Any]:
    sub = body.get("__subscription") or {}
    plan_code = (sub.get("plan_code") or "").strip().lower()
    if not plan_code:
        return {
            "ok": False,
            "error": "subscription_plan_missing",
            "root_cause": "subscription was injected but plan_code is missing",
            "fix": "Repair user_subscriptions.plan_code or subscription_guard response.",
        }

    limits = get_plan_limits(plan_code)
    if not limits.get("ok"):
        return limits

    return {
        "ok": True,
        "plan_code": plan_code,
        "daily_answers_limit": int(limits.get("daily_answers_limit") or 0),
        "ai_credits_total": int(limits.get("ai_credits_total") or 0),
        "plan_limits": limits,
    }


def _extract_cache_id(row: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(row, dict):
        return None
    return str(row.get("id") or "").strip() or None


def ask_guarded(body: Dict[str, Any]) -> Dict[str, Any]:
    question = (body.get("question") or "").strip()
    if not question:
        return {
            "ok": False,
            "error": "question_required",
            "root_cause": "missing_question",
            "fix": "Provide a non-empty question string.",
        }

    lang = (body.get("lang") or "en").strip() or "en"
    provider = (body.get("provider") or "web").strip() or "web"
    normalized_question = normalize_question_for_cache(question)
    canonical_key = derive_canonical_key(question, lang=lang)

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

    bypass = bool(body.get("__bypass"))
    subscription_bypass = bool(body.get("__subscription_bypass"))

    if bypass and not _truthy(os.getenv("ALLOW_DEV_BYPASS", "1")):
        return {
            "ok": False,
            "error": "bypass_disabled",
            "root_cause": "__bypass provided but ALLOW_DEV_BYPASS=0",
            "fix": "Remove bypass headers or set ALLOW_DEV_BYPASS=1 in backend env.",
        }

    plan_ctx: Dict[str, Any] = {
        "ok": True,
        "plan_code": None,
        "daily_answers_limit": 0,
        "ai_credits_total": 0,
    }

    if not subscription_bypass:
        plan_ctx = _resolve_plan_context(body)
        if not plan_ctx.get("ok"):
            return {
                "ok": False,
                "error": plan_ctx.get("error") or "plan_context_failed",
                "root_cause": plan_ctx.get("root_cause"),
                "fix": plan_ctx.get("fix"),
                "details": plan_ctx.get("details"),
                "debug": {**translation_debug},
            }

        daily = enforce_daily_limit(account_id, int(plan_ctx.get("daily_answers_limit") or 0))
        if not daily.get("ok"):
            return {
                "ok": False,
                "error": daily.get("error") or "daily_limit_check_failed",
                "root_cause": daily.get("root_cause"),
                "fix": daily.get("fix"),
                "details": daily.get("details"),
                "debug": {**translation_debug, "plan_code": plan_ctx.get("plan_code")},
            }

    cached = answer_from_cache(question, lang=lang, canonical_key=canonical_key)
    if cached:
        try:
            increment_cache_use(cached.get("id"))
        except Exception:
            pass

        if not subscription_bypass:
            usage = increment_daily_usage(account_id, inc=1)
            if not usage.get("ok"):
                return {
                    "ok": False,
                    "error": usage.get("error") or "daily_usage_update_failed",
                    "root_cause": usage.get("root_cause"),
                    "fix": usage.get("fix"),
                    "details": usage.get("details"),
                    "debug": {**translation_debug, "plan_code": plan_ctx.get("plan_code"), "from_cache": True},
                }

        semantic_runtime = semantic_write_runtime(
            account_id=account_id,
            question=question,
            answer=str(cached.get("answer") or ""),
            source="cache",
            provider=provider,
            lang=lang,
            normalized_question=normalized_question,
            canonical_key=canonical_key,
            cache_id=_extract_cache_id(cached),
        )

        return {
            "ok": True,
            "answer": cached.get("answer"),
            "from_cache": True,
            "account_id": account_id,
            "subscription": body.get("__subscription"),
            "plan_code": plan_ctx.get("plan_code"),
            "usage_charged": True if not subscription_bypass else False,
            "credits_consumed": 0,
            "history_written": bool((semantic_runtime.get("history_result") or {}).get("ok")),
            "embedding_written": bool((semantic_runtime.get("embedding_result") or {}).get("ok")),
            "embedding_id": semantic_runtime.get("embedding_id"),
            "debug": {
                **translation_debug,
                "canonical_key": canonical_key,
                "semantic_runtime": semantic_runtime,
            },
        }

    if not bypass and not subscription_bypass:
        bal = check_credit_balance(account_id, cost=1)
        if not bal.get("ok"):
            return {
                "ok": False,
                "error": bal.get("error") or "credit_check_failed",
                "root_cause": bal.get("root_cause") or bal.get("error"),
                "fix": bal.get("fix") or "Fix credits table/RLS.",
                "details": bal.get("details") or {"account_id": account_id},
                "debug": {**translation_debug, "plan_code": plan_ctx.get("plan_code")},
            }

    try:
        ai = call_ai(
            question=question,
            lang=lang,
            channel=(body.get("channel") or "web"),
        )
    except Exception as e:
        return {
            "ok": False,
            "error": "ai_call_failed",
            "root_cause": f"{type(e).__name__}: {_clip(str(e))}",
            "fix": "Check AI provider keys, network access, and ai_service configuration.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug, "plan_code": plan_ctx.get("plan_code"), "canonical_key": canonical_key},
        }

    if not isinstance(ai, dict) or not ai.get("ok"):
        return {
            "ok": False,
            "error": "ai_failed",
            "root_cause": (ai or {}).get("root_cause") or (ai or {}).get("error") or "unknown_ai_failure",
            "fix": (ai or {}).get("fix") or "Inspect ai_service logs.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug, "plan_code": plan_ctx.get("plan_code"), "canonical_key": canonical_key},
        }

    answer_text = (ai.get("answer") or "").strip()
    if not answer_text:
        return {
            "ok": False,
            "error": "ai_empty_answer",
            "root_cause": "AI returned ok=True but answer was empty",
            "fix": "Check ai_service provider response parsing.",
            "details": {"account_id": account_id},
            "debug": {**translation_debug, "plan_code": plan_ctx.get("plan_code"), "canonical_key": canonical_key},
        }

    if not subscription_bypass:
        usage = increment_daily_usage(account_id, inc=1)
        if not usage.get("ok"):
            return {
                "ok": False,
                "error": usage.get("error") or "daily_usage_update_failed",
                "root_cause": usage.get("root_cause"),
                "fix": usage.get("fix"),
                "details": usage.get("details"),
                "debug": {**translation_debug, "plan_code": plan_ctx.get("plan_code"), "canonical_key": canonical_key},
            }

    credits_consumed = 0
    if not bypass and not subscription_bypass:
        consume = consume_credits(account_id, cost=1)
        if not consume.get("ok"):
            return {
                "ok": False,
                "error": consume.get("error") or "credit_consume_failed",
                "root_cause": consume.get("root_cause"),
                "fix": consume.get("fix"),
                "details": consume.get("details"),
                "debug": {**translation_debug, "plan_code": plan_ctx.get("plan_code"), "canonical_key": canonical_key},
            }
        credits_consumed = 1

    cache_write_warning = None
    cache_id: Optional[str] = None
    try:
        cache_res = upsert_ai_answer_to_cache_best_effort(
            normalized_question=question,
            answer=answer_text,
            source="ai",
            lang=lang,
            canonical_key=canonical_key,
            enabled=True,
            priority=0,
        )

        if isinstance(cache_res, dict):
            cache_row = cache_res.get("cache") or cache_res.get("row") or cache_res.get("data") or cache_res
            if isinstance(cache_row, dict):
                cache_id = str(cache_row.get("id") or "").strip() or None
    except Exception as e:
        cache_write_warning = f"{type(e).__name__}: {_clip(str(e))}"

    if not cache_id:
        try:
            lookup = answer_from_cache(question, lang=lang, canonical_key=canonical_key)
            cache_id = _extract_cache_id(lookup)
        except Exception:
            pass

    semantic_runtime = semantic_write_runtime(
        account_id=account_id,
        question=question,
        answer=answer_text,
        source="ai",
        provider=provider,
        lang=lang,
        normalized_question=normalized_question,
        canonical_key=canonical_key,
        cache_id=cache_id,
    )

    return {
        "ok": True,
        "answer": answer_text,
        "from_cache": False,
        "account_id": account_id,
        "subscription": body.get("__subscription"),
        "plan_code": plan_ctx.get("plan_code"),
        "usage_charged": True if not subscription_bypass else False,
        "credits_consumed": credits_consumed,
        "history_written": bool((semantic_runtime.get("history_result") or {}).get("ok")),
        "embedding_written": bool((semantic_runtime.get("embedding_result") or {}).get("ok")),
        "embedding_id": semantic_runtime.get("embedding_id"),
        "debug": {
            **translation_debug,
            "canonical_key": canonical_key,
            "cache_id": cache_id,
            "cache_write_warning": cache_write_warning,
            "semantic_runtime": semantic_runtime,
        },
    }
