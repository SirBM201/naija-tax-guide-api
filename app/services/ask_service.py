# app/services/ask_service.py
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from datetime import date
import time

from ..core.supabase_client import supabase

from .ai_service import ask_ai, ask_ai_chat, last_ai_error
from .subscriptions_service import get_subscription_status


# -----------------------------
# Constants / knobs
# -----------------------------
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days
MAX_QUESTION_CHARS = 2000


# -----------------------------
# Helpers
# -----------------------------
def _today_yyyy_mm_dd() -> str:
    return date.today().isoformat()


def _safe_str(v: Any) -> str:
    return (v or "").strip()


def _truncate(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n]


def _now_epoch() -> int:
    return int(time.time())


# -----------------------------
# Subscription status (best effort)
# -----------------------------
def _get_subscription_status_best_effort(account_id: str, provider: str, provider_user_id: Optional[str]) -> Dict[str, Any]:
    """
    Wrapper around subscriptions_service.get_subscription_status.
    If anything fails, return an expired-ish state to be safe.
    """
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
# Credits / Limits (ai_credit_ledger)
# -----------------------------
def _consume_ai_credits(account_id: str, cost: int = 1) -> Tuple[bool, str]:
    """
    Deduct credits using an RPC if available.
    Your DB should expose: consume_ai_credits(account_id uuid, cost int)
    Returns: (ok, reason)
    """
    cost = int(cost or 1)
    if cost < 1:
        cost = 1

    try:
        res = supabase().rpc("consume_ai_credits", {"p_account_id": account_id, "p_cost": cost}).execute()
        data = getattr(res, "data", None)

        # Expecting data like: {"ok": true, "reason": "ok"} OR {"ok": false, "reason":"no_credits"}
        if isinstance(data, dict):
            ok = bool(data.get("ok"))
            reason = _safe_str(data.get("reason")) or ("ok" if ok else "no_credits")
            return ok, reason

        # If RPC returns boolean directly
        if isinstance(data, bool):
            return (data is True), ("ok" if data else "no_credits")

        return False, "credits_rpc_unexpected_response"

    except Exception:
        return False, "credits_rpc_failed"


# -----------------------------
# QA Cache (qa_cache table)
# -----------------------------
def _find_cached_answer(question: str, lang: str = "en") -> Optional[str]:
    q = _truncate(_safe_str(question), MAX_QUESTION_CHARS)
    if not q:
        return None

    try:
        res = (
            supabase()
            .table("qa_cache")
            .select("answer, created_at")
            .eq("question", q)
            .eq("lang", lang)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = getattr(res, "data", None) or []
        if not rows:
            return None
        ans = _safe_str(rows[0].get("answer"))
        return ans or None
    except Exception:
        return None


def _store_cached_answer(question: str, answer: str, lang: str = "en") -> None:
    q = _truncate(_safe_str(question), MAX_QUESTION_CHARS)
    a = _safe_str(answer)
    if not q or not a:
        return

    try:
        supabase().table("qa_cache").insert(
            {
                "question": q,
                "answer": a,
                "lang": lang,
                "created_at": _now_epoch(),
                "ttl_seconds": CACHE_TTL_SECONDS,
            }
        ).execute()
    except Exception:
        return


# -----------------------------
# AI call
# -----------------------------
def _call_ai_model(question: str, lang: str = "en") -> str:
    ans = ask_ai(question, lang=lang)
    if not ans:
        raise RuntimeError(last_ai_error() or "ai_failed")
    return ans


# -----------------------------
# Public: single-turn ask
# -----------------------------
def ask_guarded(
    question: str,
    account_id: str,
    channel: str = "web_ask",
    provider: str = "web",
    provider_user_id: Optional[str] = None,
    lang: str = "en",
) -> Dict[str, Any]:
    question = _truncate(_safe_str(question), MAX_QUESTION_CHARS)
    if not question:
        return {"ok": False, "error": "question_required", "answer": ""}

    # Subscription check
    sub = _get_subscription_status_best_effort(account_id, provider, provider_user_id)
    if not sub.get("active"):
        return {
            "ok": False,
            "error": "subscription_required",
            "answer": "Please activate a plan to use NaijaTax Guide.",
            "meta": {"channel": channel, "subscription": sub},
        }

    # Cache lookup first (cheap)
    cached = _find_cached_answer(question, lang=lang)
    if cached:
        return {
            "ok": True,
            "answer": cached,
            "meta": {"channel": channel, "mode": "cache"},
        }

    # Enforce AI credits
    ok, reason = _consume_ai_credits(account_id=account_id, cost=1)
    if not ok:
        return {
            "ok": False,
            "error": reason or "no_credits",
            "answer": "You’ve reached your usage limit for now. Please top up or wait for your next reset.",
            "meta": {"channel": channel, "mode": "blocked"},
        }

    # AI
    try:
        answer = _call_ai_model(question, lang=lang)
    except Exception as e:
        return {
            "ok": False,
            "error": str(e) or "ai_failed",
            "answer": "Sorry — I couldn’t generate a response right now. Please try again.",
            "meta": {"channel": channel, "mode": "ai_failed"},
        }

    # Store in cache
    _store_cached_answer(question, answer, lang=lang)

    return {
        "ok": True,
        "answer": answer,
        "meta": {"channel": channel, "mode": "ai", "credits_deducted": 1},
    }


# -----------------------------
# Public: chat ask (sessions + history)
# -----------------------------
def ask_chat_guarded(
    *,
    messages: list[dict[str, str]],
    account_id: str,
    provider: str = "web",
    lang: str = "en",
) -> Dict[str, Any]:
    """
    Chat-style ask with credit/subscription enforcement.

    - enforces subscription state
    - deducts 1 AI credit per assistant response
    - does NOT use QA cache (history makes caching unreliable)
    """
    provider = (provider or "web").strip().lower()

    sub = _get_subscription_status_best_effort(account_id, provider, None)
    if not (sub or {}).get("active"):
        return {
            "ok": False,
            "error": "subscription_required",
            "answer": "Please activate a plan to use the Tax Assistant Chat.",
        }

    ok, reason = _consume_ai_credits(account_id=account_id, cost=1)
    if not ok:
        return {
            "ok": False,
            "error": reason or "no_credits",
            "answer": "You’ve reached your usage limit for now. Please top up or wait for your next reset.",
        }

    ans = ask_ai_chat(messages, lang=lang)
    if not ans:
        return {
            "ok": False,
            "error": last_ai_error() or "ai_failed",
            "answer": "Sorry — I couldn’t generate a response right now. Please try again.",
        }

    return {
        "ok": True,
        "answer": ans,
        "meta": {"mode": "chat", "credits_deducted": 1},
    }
