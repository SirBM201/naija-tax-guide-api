# app/services/ask_service.py

from datetime import datetime, timezone
from app.services.accounts_service import get_or_create_account
from app.services.ai_service import generate_ai_answer


def handle_ask(provider, provider_user_id, question, lang="en"):
    """
    Master Ask Handler
    Used by Web / WhatsApp / Telegram / FB / IG / Email
    """

    # 1️⃣ Ensure account exists (AUTO CREATE)
    account = get_or_create_account(
        provider=provider,
        provider_user_id=provider_user_id,
    )

    if not account:
        return {
            "ok": False,
            "message": "Unable to create account.",
        }

    # 2️⃣ Subscription check
    expiry = account.get("plan_expiry")

    if not expiry:
        return {
            "ok": False,
            "message": "Subscription required to ask questions.",
            "reason": "no_subscription",
            "plan_expiry": None,
        }

    if expiry < datetime.now(timezone.utc).isoformat():
        return {
            "ok": False,
            "message": "Subscription expired.",
            "reason": "expired",
            "plan_expiry": expiry,
        }

    # 3️⃣ Generate AI Answer
    answer = generate_ai_answer(question, lang)

    return {
        "ok": True,
        "answer": answer,
        "plan_expiry": expiry,
    }
