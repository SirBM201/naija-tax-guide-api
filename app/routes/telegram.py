from __future__ import annotations

import inspect
from typing import Any, Dict

from flask import Blueprint, jsonify, request

from app.services.accounts_service import lookup_account, upsert_account
from app.services.ask_service import ask_guarded
from app.services.channel_linking_service import consume_and_link, extract_code
from app.services.outbound_service import send_telegram_text
from app.services.channel_identity_runtime_service import sync_channel_identity_runtime

bp = Blueprint("telegram", __name__)


def _clip(value: Any, limit: int = 260) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "…"


def _build_ask_payload(*, account_id: str, tg_user_id: str, text: str) -> Dict[str, Any]:
    """
    Build a broad alias-rich payload so Telegram can survive ask_service naming drift.

    Reason:
    - web and telegram entrypoints have diverged a few times
    - ask_guarded signature may expect question/query/text/message or other keyword names
    - we inspect the signature later and pass only supported kwargs
    """
    clean_text = (text or "").strip()
    return {
        "account_id": account_id,
        "provider": "tg",
        "channel": "tg",
        "platform": "telegram",
        "source": "telegram",
        "provider_user_id": tg_user_id,
        "channel_user_id": tg_user_id,
        "question": clean_text,
        "query": clean_text,
        "text": clean_text,
        "message": clean_text,
        "user_message": clean_text,
        "user_query": clean_text,
        "lang": "en",
        "mode": "text",
    }


def _call_ask_guarded(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Inspect ask_guarded and call it with keyword args only.
    This avoids positional-call failures and helps expose the next mismatch clearly.
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

        filtered_kwargs = {k: v for k, v in payload.items() if has_var_kwargs or k in accepted_names}

        missing_required = []
        for p in params:
            if p.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            ):
                if p.default is inspect._empty and p.name not in filtered_kwargs:
                    missing_required.append(p.name)

        if missing_required:
            return {
                "ok": False,
                "error": "ask_guarded_signature_mismatch",
                "root_cause": f"Missing required ask_guarded args: {', '.join(missing_required)}",
                "fix": "Align Telegram payload keys with app.services.ask_service.ask_guarded signature.",
                "details": {
                    "accepted_names": sorted(list(accepted_names)),
                    "payload_keys": sorted(list(payload.keys())),
                },
            }

        resp = ask_guarded(**filtered_kwargs)
        if isinstance(resp, dict):
            return resp

        return {
            "ok": False,
            "error": "ask_guarded_invalid_response",
            "root_cause": f"ask_guarded returned non-dict response: {type(resp).__name__}",
            "fix": "Ensure ask_guarded returns a dict with answer/message metadata.",
            "details": {"response_type": str(type(resp))},
        }
    except Exception as e:
        return {
            "ok": False,
            "error": "ask_guarded_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check app.services.ask_service.ask_guarded expected signature and internal dependencies.",
            "details": {"payload": payload},
        }


def _safe_sync_runtime_identity(
    *,
    account_id: str,
    tg_user_id: str,
    display_name: str | None,
    username: str | None,
    chat_type: str | None,
) -> Dict[str, Any]:
    """
    Auto-correct Telegram provider_user_id whenever the real inbound Telegram id changes.
    We intentionally use tg_user_id as the canonical runtime id because your existing
    Telegram account/linking flow is keyed on provider='tg' + provider_user_id=tg_user_id.
    """
    try:
        return sync_channel_identity_runtime(
            account_id=account_id,
            channel_type="telegram",
            provider_user_id=str(tg_user_id).strip(),
            display_name=display_name,
            metadata_patch={
                "telegram_username": (username or "").strip() or None,
                "telegram_chat_type": (chat_type or "").strip() or None,
                "telegram_runtime_sync": True,
            },
        )
    except Exception as e:
        return {
            "ok": False,
            "error": "telegram_runtime_sync_failed",
            "root_cause": f"{type(e).__name__}: {_clip(e)}",
            "fix": "Check app.services.channel_identity_runtime_service.sync_channel_identity_runtime and channel_identities table shape.",
        }


@bp.post("/telegram/webhook")
def tg_webhook():
    """
    Flow:
    - Upsert shell account (provider=tg)
    - If not linked: accept 8-char code and link OR instruct
    - If linked: runtime-sync the real Telegram provider_user_id
    - Then treat message as a question -> ask_guarded -> send answer
    """
    update = request.get_json(silent=True) or {}

    msg = update.get("message") or update.get("edited_message") or {}
    if not msg:
        return jsonify({"ok": True, "ignored": True})

    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    chat_type = chat.get("type")

    text = (msg.get("text") or "").strip()

    user = msg.get("from") or {}
    tg_user_id = str(user.get("id") or "").strip()
    tg_username = (user.get("username") or "").strip() or None

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
                linked_account_id = str(attempt.get("account_id") or "").strip()
                runtime_sync = None
                if linked_account_id:
                    runtime_sync = _safe_sync_runtime_identity(
                        account_id=linked_account_id,
                        tg_user_id=tg_user_id,
                        display_name=display_name,
                        username=tg_username,
                        chat_type=chat_type,
                    )

                send_telegram_text(
                    chat_id,
                    "✅ Telegram linked successfully!\nNow send your tax question here anytime.",
                )
                return jsonify(
                    {
                        "ok": True,
                        "linked": True,
                        "linked_now": True,
                        "account_id": attempt.get("account_id"),
                        "auth_user_id": attempt.get("auth_user_id"),
                        "runtime_sync": runtime_sync,
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
        account_id = str(lk.get("account_id") or "").strip()
        runtime_sync = None
        if account_id:
            runtime_sync = _safe_sync_runtime_identity(
                account_id=account_id,
                tg_user_id=tg_user_id,
                display_name=display_name,
                username=tg_username,
                chat_type=chat_type,
            )

        send_telegram_text(
            chat_id,
            "Welcome! Your Telegram is linked ✅. Send your tax question anytime.",
        )
        return jsonify({"ok": True, "linked": True, "runtime_sync": runtime_sync})

    account_id = str(lk.get("account_id") or "").strip()
    if not account_id:
        send_telegram_text(
            chat_id,
            "❌ Question processing failed.\n"
            "Reason: missing_account_id\n"
            "Details: Telegram channel is linked but no canonical account_id was returned.\n"
            "Fix: Check accounts_service.lookup_account and accounts.account_id population.",
        )
        return jsonify({"ok": False, "stage": "missing_account_id", "lookup": lk}), 200

    runtime_sync = _safe_sync_runtime_identity(
        account_id=account_id,
        tg_user_id=tg_user_id,
        display_name=display_name,
        username=tg_username,
        chat_type=chat_type,
    )

    payload = _build_ask_payload(account_id=account_id, tg_user_id=tg_user_id, text=text)
    resp = _call_ask_guarded(payload)

    if not resp.get("ok") and not (resp.get("answer") or resp.get("message")):
        send_telegram_text(
            chat_id,
            "❌ Question processing failed.\n"
            f"Reason: {resp.get('error', 'unknown_error')}\n"
            f"Details: {_clip(resp.get('root_cause') or resp.get('details') or 'n/a')}\n"
            f"Fix: {_clip(resp.get('fix') or 'Check ask_guarded integration and backend AI flow.')}",
        )
        return jsonify(
            {
                "ok": False,
                "stage": "ask_failed",
                "details": resp,
                "runtime_sync": runtime_sync,
            }
        ), 200

    answer = (resp.get("answer") or resp.get("message") or "").strip()
    if not answer:
        answer = "I couldn't process that right now. Please try again."

    send_telegram_text(chat_id, answer)
    return jsonify(
        {
            "ok": True,
            "linked": True,
            "ask": resp,
            "runtime_sync": runtime_sync,
        }
    )
