def _get_answer_via_existing_engine(user_key: str, question: str) -> str:
    """
    user_key here should be the WhatsApp wa_id (msg['from']).
    """
    try:
        client = current_app.test_client()
        resp = client.post(
            "/ask",
            json={
                "provider": "wa",
                "provider_user_id": user_key,   # wa_id
                "question": question,
                "mode": "text",
                "lang": "en",
            },
        )
        data = resp.get_json(silent=True) or {}
        if isinstance(data, dict) and data.get("ok") is True and data.get("answer"):
            return str(data["answer"])
        return str(data.get("message") or data.get("reason") or "Sorry, I couldn't process that right now.")
    except Exception:
        logging.exception("WhatsApp: engine call failed")
        return "Sorry — something went wrong on my side. Please try again."
