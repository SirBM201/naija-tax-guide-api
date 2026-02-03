# -------------------------------------------------
# WhatsApp inbound (Meta Cloud API – FINAL)
# -------------------------------------------------

@bp.post("/inbound/whatsapp")
def whatsapp_inbound():
    body = request.get_json(silent=True) or {}

    try:
        entry = body["entry"][0]
        change = entry["changes"][0]
        value = change["value"]

        messages = value.get("messages")
        if not messages:
            # Delivery receipt / status update – ignore safely
            return jsonify({"ok": True, "ignored": True, "reason": "no_messages"}), 200

        msg = messages[0]
        wa_user_id = str(msg.get("from", "")).strip()
        msg_type = msg.get("type")

        if msg_type != "text":
            # For now, only text is supported
            return jsonify({"ok": True, "ignored": True, "reason": "non_text_message"}), 200

        text = (msg.get("text", {}) or {}).get("body", "").strip()

    except Exception:
        return jsonify({"ok": False, "error": "invalid_whatsapp_payload"}), 400

    if not wa_user_id or not text:
        return jsonify({"ok": False, "error": "missing_sender_or_text"}), 400

    # Ensure account exists
    account = upsert_account(
        provider="wa",
        provider_user_id=wa_user_id,
    )

    # LINK <code> support
    link_result = _maybe_link_from_message("wa", text)
    if link_result:
        return jsonify({"ok": True, "linked": True}), 200

    # Normal AI question flow
    resp = ask_guarded(
        {
            "account_id": account["id"],
            "question": text,
        }
    )
    return jsonify(resp), 200
