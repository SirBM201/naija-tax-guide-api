# app/services/ask_service.py
from __future__ import annotations

import os
import time
from datetime import date
from typing import Any, Dict, Optional, Tuple, Union

from ..core.supabase_client import supabase

from .ai_service import ask_ai, ask_ai_chat, last_ai_error
from .subscriptions_service import get_subscription_status
from .qa_cache_service import (
    find_cached_answer,
    touch_cache_best_effort,
    upsert_ai_answer_to_cache_best_effort,
)
from .question_canonicalizer import basic_normalize, canonical_key
from .response_refiner import refine_answer
from .qa_usage_service import try_consume_cache_slot, get_cache_used_today


# -----------------------------
# Constants / knobs
# -----------------------------
MAX_QUESTION_CHARS = 2000

PAID_CACHE_DAILY_LIMIT = int((os.getenv("PAID_CACHE_DAILY_LIMIT", "1000") or "1000").strip())
FREE_CACHE_DAILY_LIMIT = int((os.getenv("FREE_CACHE_DAILY_LIMIT", "20") or "20").strip())

HARD_DAILY_MAX = int((os.getenv("HARD_DAILY_MAX", "1500") or "1500").strip())


# -----------------------------
# Debug
# -----------------------------
def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _debug_enabled() -> bool:
    return _truthy(os.getenv("ASK_DEBUG")) or _truthy(os.getenv("WEB_AUTH_DEBUG"))


def _dbg_pack(**kv: Any) -> Dict[str, Any]:
    if not _debug_enabled():
        return {}
    return dict(kv)


# -----------------------------
# Helpers
# -----------------------------
def _safe_str(v: Any) -> str:
    return (v or "").strip()


def _truncate(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n]


def _sb():
    return supabase() if callable(supabase) else supabase


def _dev_bypass_enabled(payload: Dict[str, Any]) -> bool:
    # Enabled only when routes/ask.py sets __bypass=True after validating token
    return bool(payload.get("__bypass") is True)


def _resolve_account_id(payload: Dict[str, Any]) -> Optional[str]:
    """
    Resolve account_id from payload:
    - if account_id present, use it
    - else if (provider, provider_user_id), lookup in accounts table
    """
    account_id = _safe_str(payload.get("account_id"))
    if account_id:
        return account_id

    provider = _safe_str(payload.get("provider")).lower()
    provider_user_id = _safe_str(payload.get("provider_user_id"))
    if not provider or not provider_user_id:
        return None

    try:
        res = (
            _sb()
            .table("accounts")
            .select("account_id")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return None
        return _safe_str(rows[0].get("account_id")) or None
    except Exception:
        return None


# -----------------------------
# Subscription status (best effort)
# -----------------------------
def _get_subscription_status_best_effort(account_id: str, provider: str, provider_user_id: Optional[str]) -> Dict[str, Any]:
    try:
        return get_subscription_status(account_id, provider, provider_user_id)
    except Exception:
        return {
            "active": False,
            "state": "none",
            "reason": "subscription_check_failed",
            "plan_code": None,
            "expires_at": None,
            "grace_until": None,
        }


# -----------------------------
# Credits / Limits (RPC: consume_ai_credits)
# -----------------------------
def _consume_ai_credits(account_id: str, cost: int = 1) -> Tuple[bool, str, Dict[str, Any]]:
    cost = int(cost or 1)
    if cost < 1:
        cost = 1

    dbg: Dict[str, Any] = {"rpc": "consume_ai_credits", "cost": cost}

    try:
        res = _sb().rpc("consume_ai_credits", {"p_account_id": account_id, "p_cost": cost}).execute()
        data = getattr(res, "data", None)

        if isinstance(data, dict):
            ok = bool(data.get("ok"))
            reason = _safe_str(data.get("reason")) or ("ok" if ok else "no_credits")
            dbg.update({"rpc_ok": ok, "rpc_reason": reason})
            return ok, reason, dbg

        if isinstance(data, bool):
            dbg.update({"rpc_ok": bool(data)})
            return (data is True), ("ok" if data else "no_credits"), dbg

        dbg.update({"rpc_ok": False, "rpc_reason": "unexpected_response"})
        return False, "credits_rpc_unexpected_response", dbg

    except Exception as e:
        dbg.update({"rpc_ok": False, "rpc_reason": "rpc_failed"})
        if _debug_enabled():
            dbg.update({"error_type": type(e).__name__, "error": str(e)[:220]})
        return False, "credits_rpc_failed", dbg


# -----------------------------
# AI call
# -----------------------------
def _call_ai_model(question: str, lang: str = "en") -> str:
    ans = ask_ai(question, lang=lang)
    if not ans:
        raise RuntimeError(last_ai_error() or "ai_failed")
    return ans


def _cache_limit_message(used: int, limit: int) -> str:
    return (
        f"You’ve reached today’s fast-answer limit ({used}/{limit}).\n\n"
        "To continue now:\n"
        "• Try again tomorrow (limit resets daily), or\n"
        "• Use AI credits if available by asking a new question."
    )


# -----------------------------
# Public: unified ask (dict payload)
# -----------------------------
def ask_guarded(payload: Union[Dict[str, Any], str], *args, **kwargs) -> Dict[str, Any]:
    """
    Supports dict payloads used by routes.
    Backwards compatible if called with (question, account_id,...).
    """
    if isinstance(payload, str):
        question = payload
        account_id = kwargs.get("account_id") or (args[0] if args else None)
        if not account_id:
            return {"ok": False, "error": "account_required", "answer": ""}
        return _ask_guarded_dict(
            {
                "question": question,
                "account_id": account_id,
                "provider": kwargs.get("provider") or "web",
                "provider_user_id": kwargs.get("provider_user_id"),
                "lang": kwargs.get("lang") or "en",
                "channel": kwargs.get("channel") or "ask",
            }
        )

    if not isinstance(payload, dict):
        return {"ok": False, "error": "invalid_request", "answer": ""}

    return _ask_guarded_dict(payload)


def _ask_guarded_dict(payload: Dict[str, Any]) -> Dict[str, Any]:
    question = _truncate(_safe_str(payload.get("question")), MAX_QUESTION_CHARS)
    provider = (_safe_str(payload.get("provider")) or "web").lower()
    provider_user_id = _safe_str(payload.get("provider_user_id")) or None
    lang = _safe_str(payload.get("lang")) or "en"
    channel = _safe_str(payload.get("channel")) or ("web_ask" if provider == "web" else "ask")

    if not question:
        return {"ok": False, "error": "question_required", "answer": ""}

    account_id = _resolve_account_id(payload)
    if not account_id:
        return {"ok": False, "error": "account_required", "answer": ""}

    bypass = _dev_bypass_enabled(payload)

    debug: Dict[str, Any] = _dbg_pack(
        stage="start",
        provider=provider,
        lang=lang,
        channel=channel,
        dev_bypass=bypass,
    )

    # 1) Subscription check (SKIP when dev bypass)
    if not bypass:
        sub = _get_subscription_status_best_effort(account_id, provider, provider_user_id)
        debug.update(_dbg_pack(stage="subscription_checked", subscription_state=sub.get("state"), sub_reason=sub.get("reason")))

        if not sub.get("active"):
            out = {
                "ok": False,
                "error": "subscription_required",
                "answer": "Please activate a plan to use NaijaTax Guide.",
                "meta": {"channel": channel, "subscription": sub},
            }
            if _debug_enabled():
                out["meta"]["debug"] = debug
            return out
    else:
        # Dev bypass pretends active
        sub = {"active": True, "state": "dev_bypass", "plan_code": "DEV", "reason": "dev_bypass"}

    # Determine cache limit (paid if active)
    cache_limit = PAID_CACHE_DAILY_LIMIT if sub.get("active") else FREE_CACHE_DAILY_LIMIT

    # 2) Cache lookup
    normalized = basic_normalize(question)
    ck = canonical_key(question)

    cache_row = find_cached_answer(
        normalized_question=normalized,
        lang=lang,
        canonical_key=ck,
    )

    debug.update(_dbg_pack(stage="cache_checked", canonical_key=ck, cache_hit=bool(cache_row)))

    if cache_row and cache_row.get("answer"):
        # Enforce daily cache limit (SKIP when dev bypass)
        if not bypass:
            used_before = get_cache_used_today(account_id)
            ok_slot, usage_dbg = try_consume_cache_slot(account_id, cache_limit)
            debug.update(_dbg_pack(stage="cache_limit_checked", cache_used_before=used_before, cache_limit=cache_limit, usage=usage_dbg))

            if not ok_slot:
                out = {
                    "ok": False,
                    "error": "cache_limit_reached",
                    "answer": _cache_limit_message(used_before, cache_limit),
                    "meta": {
                        "channel": channel,
                        "mode": "blocked_cache_limit",
                        "cache_daily_limit": cache_limit,
                        "cache_used_today": used_before,
                    },
                }
                if _debug_enabled():
                    out["meta"]["debug"] = debug
                return out

        cid = _safe_str(cache_row.get("id")) or ""
        if cid:
            touch_cache_best_effort(cid)

        refined = refine_answer(cache_row.get("answer"), lang=lang, source="cache", provider=provider) or cache_row.get("answer")

        out = {"ok": True, "answer": refined, "meta": {"channel": channel, "mode": "cache", "canonical_key": ck}}
        if _debug_enabled():
            out["meta"]["debug"] = debug
        return out

    # 3) AI credits (SKIP when dev bypass)
    if not bypass:
        ok_credits, reason, credits_dbg = _consume_ai_credits(account_id=account_id, cost=1)
        debug.update(_dbg_pack(stage="credits_consumed", credits=credits_dbg))

        if not ok_credits:
            out = {
                "ok": False,
                "error": reason or "no_credits",
                "answer": "You’ve reached your AI credit limit for now. Please top up or wait for your next reset.",
                "meta": {"channel": channel, "mode": "blocked_credits"},
            }
            if _debug_enabled():
                out["meta"]["debug"] = debug
            return out

    # 4) AI generation
    try:
        raw = _call_ai_model(question, lang=lang)
        refined = refine_answer(raw, lang=lang, source="ai", provider=provider)
        if not refined:
            raise RuntimeError("ai_refine_failed")
        answer = refined
        debug.update(_dbg_pack(stage="ai_ok", ai_len=len(answer)))
    except Exception as e:
        debug.update(_dbg_pack(stage="ai_failed", ai_error=str(e)[:200], last_ai_error=(last_ai_error() or "")[:200]))
        out = {
            "ok": False,
            "error": str(e) or "ai_failed",
            "answer": "Sorry — I couldn’t generate a response right now. Please try again.",
            "meta": {"channel": channel, "mode": "ai_failed"},
        }
        if _debug_enabled():
            out["meta"]["debug"] = debug
        return out

    # 5) Save AI answer to cache (best effort)
    upsert_ai_answer_to_cache_best_effort(
        normalized_question=normalized,
        answer=answer,
        tags=None,
        source="ai",
        lang=lang,
        canonical_key=ck,
        enabled=True,
        priority=0,
    )

    out = {
        "ok": True,
        "answer": answer,
        "meta": {
            "channel": channel,
            "mode": "ai",
            "credits_deducted": 0 if bypass else 1,
            "canonical_key": ck,
            "dev_bypass": bypass,
        },
    }
    if _debug_enabled():
        out["meta"]["debug"] = debug
    return out


def ask_chat_guarded(
    *,
    messages: list[dict[str, str]],
    account_id: str,
    provider: str = "web",
    lang: str = "en",
) -> Dict[str, Any]:
    """
    Chat-style ask with credit/subscription enforcement.
    """
    provider = (provider or "web").strip().lower()

    sub = _get_subscription_status_best_effort(account_id, provider, None)
    if not (sub or {}).get("active"):
        return {"ok": False, "error": "subscription_required", "answer": "Please activate a plan to use the Tax Assistant Chat."}

    ok, reason, _ = _consume_ai_credits(account_id=account_id, cost=1)
    if not ok:
        return {"ok": False, "error": reason or "no_credits", "answer": "You’ve reached your AI credit limit for now. Please top up or wait for your next reset."}

    ans = ask_ai_chat(messages, lang=lang)
    if not ans:
        return {"ok": False, "error": last_ai_error() or "ai_failed", "answer": "Sorry — I couldn’t generate a response right now. Please try again."}

    return {"ok": True, "answer": ans, "meta": {"mode": "chat", "credits_deducted": 1}}
