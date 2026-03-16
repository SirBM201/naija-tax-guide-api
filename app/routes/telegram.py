from __future__ import annotations

import inspect
from typing import Any, Dict

from flask import Blueprint, jsonify, request

from app.services.accounts_service import lookup_account, upsert_account
from app.services.ask_service import ask_guarded
from app.services.channel_linking_service import consume_and_link, extract_code
from app.services.outbound_service import send_telegram_text

bp = Blueprint("telegram", __name__)


def _clip(value: Any, limit: int = 260) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "…"


def _build_ask_payload(*, tg_user_id: str, text: str) -> Dict[str, Any]:
    return {
        "provider": "tg",
        "provider_user_id": tg_user_id,
        "question": text,
        "lang": "en",
        "mode": "text",
    }


def _call_ask_guarded(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Failure-tolerant adapter for ask_guarded.

    Your logs proved that this code path is wrong:
        ask_guarded(payload)

    because current ask_guarded does NOT accept one positional dict.

    This adapter supports both common styles safely:
    1) ask_guarded(**kwargs)
    2) ask_guarded(payload)   (only if the function really expects one argument)
    """
    try:
        sig = inspect.signature(ask_guarded)
        params = list(sig.parameters.values())

        has_var_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        accepted_names = {
            p.name
            for p in params
            if p.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            )
        }

        filtered_kwargs = {k: v for k, v in payload.items() if k in accepted_names}

        # Preferred path: keyword call
        if has_var_kwargs or filtered_kwargs:
            return ask_guarded(**filtered_kwargs)

        # Legacy/single-arg path only when signature really expects exactly one argument
        positional_params = [
            p
            for p in params
            if p.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        if len(positional_params) == 1:
            return ask_guarded(payload)

        return {
            "ok": False,
            "error": "ask_guarded_signature_mismatch",
            "root_cause": f"Unsupported ask_guarded signature: {sig}",
            "fix": "Update telegram route adapter or align ask_guarded signature with web ask flow.",
            "details": {"payload_keys": list(payload.keys())},
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "ask_guarded_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check app.services.ask_service.ask_guarded expected signature and internal dependencies.",
            "details": {"payload": payload},
        }


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

    shell = upsert_account(
        provider="tg",
        provider_user_id=tg_user_id,
        display_name=display_name,
        phone=None,
    )
    if not shell.get("ok"):
        send_telegram_text(
            chat_id,
            "❌ Telegram shell account setup failed.\n"
            f"Reason: {shell.get('error', 'unknown_error')}\n"
            f"Details: {_clip(shell.get('root_cause') or shell.get('details') or 'n/a')}\n"
            f"Fix: {_clip(shell.get('fix') or 'Check backend account setup.')}",
        )
        return jsonify({"ok": False, "stage": "upsert_shell", "details": shell}), 200

    lk = lookup_account(provider="tg", provider_user_id=tg_user_id)
    if not lk.get("ok"):
        send_telegram_text(
            chat_id,
            "❌ Telegram account lookup failed.\n"
            f"Reason: {lk.get('error', 'lookup_failed')}\n"
            f"Details: {_clip(lk.get('root_cause') or lk.get('details') or 'n/a')}\n"
            f"Fix: {_clip(lk.get('fix') or 'Check accounts table access.')}",
        )
        return jsonify({"ok": False, "stage": "lookup_account", "details": lk}), 200

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
                    }
                )

            send_telegram_text(
                chat_id,
                "❌ Link failed.\n"
                f"Reason: {attempt.get('error', 'unknown_error')}\n"
                f"Details: {_clip(attempt.get('root_cause') or attempt.get('details') or 'n/a')}\n"
                f"Fix: {_clip(attempt.get('fix') or 'Check link token flow and accounts link update.')}",
            )
            return jsonify({"ok": True, "linked": False, "link_attempt": attempt}), 200

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

    payload = _build_ask_payload(tg_user_id=tg_user_id, text=text)
    resp = _call_ask_guarded(payload)

    if not isinstance(resp, dict):
        send_telegram_text(
            chat_id,
            "❌ Ask flow failed.\n"
            f"Reason: invalid_response\nDetails: {_clip(type(resp).__name__)}\n"
            "Fix: Ensure ask_guarded returns a dict like the web ask route.",
        )
        return jsonify({"ok": False, "stage": "ask_invalid_response", "response_type": str(type(resp))}), 200

    if not resp.get("ok") and not (resp.get("answer") or resp.get("message")):
        send_telegram_text(
            chat_id,
            "❌ Question processing failed.\n"
            f"Reason: {resp.get('error', 'unknown_error')}\n"
            f"Details: {_clip(resp.get('root_cause') or resp.get('details') or 'n/a')}\n"
            f"Fix: {_clip(resp.get('fix') or 'Check ask_guarded integration and backend AI flow.')}",
        )
        return jsonify({"ok": False, "stage": "ask_failed", "details": resp}), 200

    answer = (resp.get("answer") or resp.get("message") or "").strip()
    if not answer:
        answer = "I couldn't process that right now. Please try again."

    send_telegram_text(chat_id, answer)
    return jsonify({"ok": True, "linked": True, "ask": resp})
