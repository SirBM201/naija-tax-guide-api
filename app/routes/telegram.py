from __future__ import annotations

from flask import Blueprint, jsonify, request

from app.services.accounts_service import lookup_account, upsert_account
from app.services.ask_service import ask_guarded
from app.services.channel_linking_service import consume_and_link, extract_code
from app.services.outbound_service import send_telegram_text

bp = Blueprint("telegram", __name__)


@bp.post("/telegram/webhook")
def tg_webhook():
    """
    Flow:
    - Upsert shell account (provider=tg)
    - If not linked: accept 8-char code and link OR instruct
    - If linked: treat message as a question -> ask_guarded -> send answer
    """
    update = request.get_json(silent=True) or {}

    msg = update.get("message") or update.get("edited_message") or {}
    if not msg:
        return jsonify({"ok": True, "ignored": True})

    chat = msg.get("chat") or {}
    chat_id = chat.get("id")

    text = (msg.get("text") or "").strip()

    user = msg.get("from") or {}
    tg_user_id = str(user.get("id") or "").strip()
    display_name = " ".join(
        [x for x in [user.get("first_name"), user.get("last_name")] if x]
    ) or None

    if not tg_user_id or not chat_id:
        return jsonify({"ok": True, "ignored": True})

    upsert_account(
        provider="tg",
        provider_user_id=tg_user_id,
        display_name=display_name,
        phone=None,
    )

    lk = lookup_account(provider="tg", provider_user_id=tg_user_id)
    if not lk.get("ok"):
        send_telegram_text(chat_id, "System error. Please try again.")
        return jsonify({"ok": True, "error": "lookup_failed", "details": lk})

    if not lk.get("linked"):
        code = extract_code(text)

        if code:
            attempt = consume_and_link(
                provider="tg",
                code=code,
                provider_user_id=tg_user_id,
                display_name=display_name,
                phone=None,
            )

            if attempt.get("ok"):
                send_telegram_text(
                    chat_id,
                    "✅ Telegram linked successfully!\nNow send your tax question here anytime.",
                )
                return jsonify(
                    {
                        "ok": True,
                        "linked": True,
                        "linked_now": True,
                        "account_id": attempt.get("auth_user_id"),
                        "attempt": attempt,
                    }
                )

            send_telegram_text(
                chat_id,
                "❌ Link failed.\n"
                f"Reason: {attempt.get('error') or 'unknown_error'}\n"
                f"Details: {attempt.get('reason') or 'n/a'}",
            )
            return jsonify(
                {
                    "ok": True,
                    "linked": False,
                    "linked_now": False,
                    "attempt": attempt,
                }
            )

        send_telegram_text(
            chat_id,
            "Your Telegram is not linked yet.\n"
            "1) Login on the website\n"
            "2) Generate your LINK CODE\n"
            "3) Reply here with the 8-character code\n\n"
            "Example: 7K9M2H8P",
        )
        return jsonify({"ok": True, "linked": False})

    if not text:
        send_telegram_text(chat_id, "Send your question as text and I will reply.")
        return jsonify({"ok": True, "linked": True, "ignored": True, "reason": "no_text"})

    if text.lower().startswith("/start"):
        send_telegram_text(
            chat_id,
            "Welcome! Your Telegram is linked ✅. Send your tax question anytime.",
        )
        return jsonify({"ok": True, "linked": True})

    resp = ask_guarded(
        {
            "provider": "tg",
            "provider_user_id": tg_user_id,
            "question": text,
            "lang": "en",
            "mode": "text",
        }
    )

    answer = (resp.get("answer") or resp.get("message") or "").strip()
    if not answer:
        answer = "I couldn't process that right now. Please try again."

    send_telegram_text(chat_id, answer)
    return jsonify({"ok": True, "linked": True, "ask": resp})
