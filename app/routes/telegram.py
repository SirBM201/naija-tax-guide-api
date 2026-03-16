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
            }
        )
