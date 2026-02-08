# app/services/ask_service.py

from __future__ import annotations

import os
from typing import Dict, Any, Optional

from ..services.subscriptions_service import get_subscription_status
from ..core.supabase_client import supabase

try:
    from openai import OpenAI
except Exception:
    OpenAI = None  # type: ignore


# -----------------------------
# AI client (safe init)
# -----------------------------
_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
_ai_client = None

if _OPENAI_API_KEY and OpenAI is not None:
    try:
        _ai_client = OpenAI(api_key=_OPENAI_API_KEY)
    except Exception:
        _ai_client = None


_SYSTEM_PROMPT = (
    "You are Naija Tax AI — a professional Nigerian tax assistant.\n"
    "You help with:\n"
    "- FIRS tax rules\n"
    "- Freelancer tax\n"
    "- SME tax compliance\n"
    "- VAT\n"
    "- PAYE\n"
    "- Record keeping\n"
    "- Practical filing steps\n\n"
    "Be concise, accurate, and practical. Use simple English."
)


def _normalize_provider(provider: Optional[str]) -> Optional[str]:
    if not provider:
        return None
    p = provider.strip().lower()
    # allow common synonyms safely
    if p in ("whatsapp", "wa"):
        return "wa"
    if p in ("telegram", "tg"):
        return "tg"
    if p in ("web", "site", "website"):
        return "web"
    # allow future providers without breaking
    return p


def _ask_ai_text(question: str, lang: Optional[str] = None) -> str:
    """
    Returns AI answer if configured.
    Falls back safely if OpenAI is not configured.
    """
    if not _ai_client:
        return (
            "AI service is not configured yet. "
            "Please contact support or try again later."
        )

    user_msg = question
    if lang:
        user_msg = f"[Language: {lang}] {question}"

    resp = _ai_client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        temperature=0.3,
    )
    return resp.choices[0].message.content or "No answer generated."


def _log_usage_best_effort(account_id: Optional[str], question: str, answer: str) -> None:
    """
    Best-effort logging. Never blocks user response.
    If the table doesn't exist, it silently ignores.
    """
    if not account_id:
        return

    try:
        db = supabase()
        db.table("ai_usage_logs").insert(
            {
                "account_id": account_id,
                "question": question,
                "answer": answer,
            }
        ).execute()
    except Exception:
        # do not break production flow
        pass


def ask_guarded(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Guarded ask endpoint logic.

    Input supports:
      - account_id OR (provider, provider_user_id)
      - question required
      - lang optional

    Output keeps your current contract:
      ok, answer, audio_url, plan_expiry
    """
    account_id = (body.get("account_id") or "").strip() or None
    provider = _normalize_provider((body.get("provider") or "").strip() or None)
    provider_user_id = (body.get("provider_user_id") or "").strip() or None
    question = (body.get("question") or "").strip()
    lang = (body.get("lang") or "").strip() or None

    if not question:
        return {
            "ok": False,
            "reason": "missing_question",
            "message": "Question is required.",
            "plan_expiry": None,
        }

    status = get_subscription_status(
        account_id=account_id,
        provider=provider,
        provider_user_id=provider_user_id,
    )

    if not status.get("active"):
        return {
            "ok": False,
            "reason": status.get("reason", "not_subscribed"),
            "message": "Subscription required to ask questions.",
            "plan_expiry": status.get("expires_at"),
        }

    # Use AI if configured; otherwise safe fallback message
    answer = _ask_ai_text(question, lang)

    # best-effort logging (won't break if table missing)
    _log_usage_best_effort(status.get("account_id") or account_id, question, answer)

    return {
        "ok": True,
        "answer": answer,
        "audio_url": None,  # voice layer later
        "plan_expiry": status.get("expires_at"),
    }
