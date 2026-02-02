from typing import Dict, Any
from ..services.subscriptions_service import get_subscription_status

def ask_guarded(body: Dict[str, Any]) -> Dict[str, Any]:
    account_id = (body.get("account_id") or "").strip() or None
    provider = (body.get("provider") or "").strip().lower() or None
    provider_user_id = (body.get("provider_user_id") or "").strip() or None
    question = (body.get("question") or "").strip()
    lang = (body.get("lang") or "").strip() or None

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

    # Phase-1: backend returns a stub answer (or you can wire OpenAI later)
    # This avoids mixing scope now.
    answer = f"(Phase-1 stub) Received your question{f' [{lang}]' if lang else ''}: {question}"

    return {
        "ok": True,
        "answer": answer,
        "audio_url": None,
        "plan_expiry": status.get("expires_at"),
    }
