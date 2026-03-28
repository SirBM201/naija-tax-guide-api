from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import requests

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _fail(where: str, error: Any, fix: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = {
        "ok": False,
        "error": "channel_post_payment_service_failed",
        "where": where,
        "root_cause": repr(error),
        "fix": fix,
    }
    if extra:
        payload.update(extra)
    return payload


def get_account_by_account_id(account_id: str) -> Optional[Dict[str, Any]]:
    acct = _clean(account_id)
    if not acct:
        return None

    res = (
        _sb()
        .table("accounts")
        .select("*")
        .eq("account_id", acct)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def get_channel_identity(
    *,
    account_id: str,
    channel_type: str,
    provider_user_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    acct = _clean(account_id)
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)

    if not acct or not channel:
        return None

    query = (
        _sb()
        .table("channel_identities")
        .select("*")
        .eq("account_id", acct)
        .eq("channel_type", channel)
    )

    if provider_id:
        query = query.eq("provider_user_id", provider_id)

    res = query.limit(1).execute()
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def _build_success_message(
    *,
    plan_code: str,
) -> str:
    return (
        f"Payment received successfully.\n\n"
        f"Your Naija Tax Guide subscription is now active.\n"
        f"Plan: {plan_code}\n\n"
        f"You can now continue using your paid access."
    )


def _post_with_retry(
    *,
    url: str,
    json_payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    attempts: int = 3,
    backoff_seconds: float = 1.2,
) -> Dict[str, Any]:
    last_error: Optional[Exception] = None
    last_status_code: Optional[int] = None
    last_response_text: Optional[str] = None
    last_json: Optional[Dict[str, Any]] = None

    for attempt in range(1, attempts + 1):
        try:
            resp = requests.post(url, json=json_payload, headers=headers, timeout=timeout)
            last_status_code = resp.status_code

            try:
                parsed = resp.json()
            except Exception:
                parsed = {"raw_text": resp.text}

            last_json = parsed
            last_response_text = resp.text

            if resp.status_code < 500:
                return {
                    "ok": True,
                    "status_code": resp.status_code,
                    "response": parsed,
                    "attempt": attempt,
                }

        except requests.RequestException as e:
            last_error = e

        if attempt < attempts:
            time.sleep(backoff_seconds * attempt)

    if last_error is not None:
        return {
            "ok": False,
            "kind": "network_error",
            "root_cause": repr(last_error),
            "status_code": last_status_code,
            "response": last_json or {"raw_text": last_response_text},
            "attempts": attempts,
        }

    return {
        "ok": False,
        "kind": "http_error",
        "status_code": last_status_code,
        "response": last_json or {"raw_text": last_response_text},
        "attempts": attempts,
    }


def _send_whatsapp_text(
    *,
    phone_number: str,
    text: str,
) -> Dict[str, Any]:
    access_token = (
        os.getenv("WHATSAPP_ACCESS_TOKEN")
        or os.getenv("META_WHATSAPP_ACCESS_TOKEN")
        or os.getenv("WHATSAPP_TOKEN")
        or ""
    ).strip()

    phone_number_id = (
        os.getenv("WHATSAPP_PHONE_NUMBER_ID")
        or os.getenv("META_WHATSAPP_PHONE_NUMBER_ID")
        or ""
    ).strip()

    graph_version = (os.getenv("WHATSAPP_GRAPH_VERSION") or "v21.0").strip()

    if not access_token or not phone_number_id:
        return {
            "ok": False,
            "error": "whatsapp_env_missing",
            "where": "_send_whatsapp_text",
            "fix": "Set WHATSAPP_ACCESS_TOKEN and WHATSAPP_PHONE_NUMBER_ID in backend env.",
            "phone_number": phone_number,
        }

    url = f"https://graph.facebook.com/{graph_version}/{phone_number_id}/messages"
    payload = {
        "messaging_product": "whatsapp",
        "to": phone_number,
        "type": "text",
        "text": {"body": text},
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    try:
        result = _post_with_retry(
            url=url,
            json_payload=payload,
            headers=headers,
            timeout=30,
            attempts=3,
            backoff_seconds=1.0,
        )

        if not result.get("ok"):
            return {
                "ok": False,
                "error": "whatsapp_send_failed",
                "where": "_send_whatsapp_text",
                "fix": "Check WhatsApp Cloud API credentials, recipient number format, business permissions, or temporary network issues.",
                "status_code": result.get("status_code"),
                "response": result.get("response"),
                "attempts": result.get("attempts"),
                "phone_number": phone_number,
                "transport_kind": result.get("kind"),
                "root_cause": result.get("root_cause"),
            }

        if int(result.get("status_code") or 0) >= 400:
            return {
                "ok": False,
                "error": "whatsapp_send_failed",
                "where": "_send_whatsapp_text",
                "fix": "Check WhatsApp Cloud API credentials, recipient number format, and business account permissions.",
                "status_code": result.get("status_code"),
                "response": result.get("response"),
                "attempt": result.get("attempt"),
                "phone_number": phone_number,
            }

        return {
            "ok": True,
            "channel_type": "whatsapp",
            "delivery_response": result.get("response"),
            "attempt": result.get("attempt"),
        }
    except Exception as e:
        return _fail(
            "_send_whatsapp_text",
            e,
            "Check outbound internet access and WhatsApp env configuration.",
            {"phone_number": phone_number},
        )


def _send_telegram_text(
    *,
    chat_id: str,
    text: str,
) -> Dict[str, Any]:
    bot_token = (
        os.getenv("TELEGRAM_BOT_TOKEN")
        or os.getenv("TELEGRAM_TOKEN")
        or ""
    ).strip()

    if not bot_token:
        return {
            "ok": False,
            "error": "telegram_env_missing",
            "where": "_send_telegram_text",
            "fix": "Set TELEGRAM_BOT_TOKEN in backend env.",
            "chat_id": chat_id,
        }

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
    }

    try:
        result = _post_with_retry(
            url=url,
            json_payload=payload,
            headers=None,
            timeout=30,
            attempts=4,
            backoff_seconds=1.2,
        )

        if not result.get("ok"):
            return {
                "ok": False,
                "error": "telegram_send_failed",
                "where": "_send_telegram_text",
                "fix": "Check TELEGRAM_BOT_TOKEN, bot permissions, chat state, or temporary network instability.",
                "status_code": result.get("status_code"),
                "response": result.get("response"),
                "attempts": result.get("attempts"),
                "chat_id": chat_id,
                "transport_kind": result.get("kind"),
                "root_cause": result.get("root_cause"),
            }

        response = result.get("response") or {}
        if int(result.get("status_code") or 0) >= 400 or not response.get("ok", False):
            return {
                "ok": False,
                "error": "telegram_send_failed",
                "where": "_send_telegram_text",
                "fix": "Check TELEGRAM_BOT_TOKEN, bot permissions, and whether the chat has started the bot.",
                "status_code": result.get("status_code"),
                "response": response,
                "attempt": result.get("attempt"),
                "chat_id": chat_id,
            }

        return {
            "ok": True,
            "channel_type": "telegram",
            "delivery_response": response,
            "attempt": result.get("attempt"),
        }
    except Exception as e:
        return _fail(
            "_send_telegram_text",
            e,
            "Check outbound internet access and Telegram env configuration.",
            {"chat_id": chat_id},
        )


def notify_channel_payment_success(
    *,
    account_id: str,
    channel_type: str,
    plan_code: str,
    provider_user_id: Optional[str] = None,
) -> Dict[str, Any]:
    acct = _clean(account_id)
    channel = _clean(channel_type).lower()
    code = _clean(plan_code)
    provider_id = _clean(provider_user_id)

    if not acct:
        return {
            "ok": False,
            "error": "account_id_required",
            "where": "notify_channel_payment_success",
            "fix": "Pass a valid account_id.",
        }

    if channel not in {"whatsapp", "telegram"}:
        return {
            "ok": False,
            "error": "invalid_channel_type",
            "where": "notify_channel_payment_success",
            "fix": "Use whatsapp or telegram.",
            "channel_type": channel,
        }

    if not code:
        return {
            "ok": False,
            "error": "plan_code_required",
            "where": "notify_channel_payment_success",
            "fix": "Pass the active plan code.",
        }

    try:
        account = get_account_by_account_id(acct)
        if not account:
            return {
                "ok": False,
                "error": "account_not_found",
                "where": "get_account_by_account_id",
                "fix": "Confirm the account_id exists before notifying channel success.",
                "account_id": acct,
            }

        identity = get_channel_identity(
            account_id=acct,
            channel_type=channel,
            provider_user_id=provider_id or None,
        )
        if not identity and provider_id:
            identity = get_channel_identity(
                account_id=acct,
                channel_type=channel,
                provider_user_id=None,
            )

        if not identity:
            return {
                "ok": False,
                "error": "channel_identity_not_found",
                "where": "get_channel_identity",
                "fix": "Confirm the user has a linked channel identity before sending confirmation.",
                "account_id": acct,
                "channel_type": channel,
                "provider_user_id": provider_id or None,
            }

        message = _build_success_message(plan_code=code)
        metadata = identity.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}

        if channel == "whatsapp":
            actual_provider_user_id = _clean(identity.get("provider_user_id"))
            if not actual_provider_user_id:
                return {
                    "ok": False,
                    "error": "provider_user_id_missing",
                    "where": "notify_channel_payment_success",
                    "fix": "Ensure provider_user_id exists on the matched WhatsApp identity row.",
                    "identity": identity,
                }

            delivery = _send_whatsapp_text(
                phone_number=actual_provider_user_id,
                text=message,
            )
            delivery_target = actual_provider_user_id

        else:
            telegram_chat_id = _clean(
                metadata.get("telegram_chat_id")
                or metadata.get("last_runtime_chat_id")
                or metadata.get("telegram_last_chat_id")
            )
            fallback_provider_user_id = _clean(identity.get("provider_user_id"))
            delivery_target = telegram_chat_id or fallback_provider_user_id

            if not delivery_target:
                return {
                    "ok": False,
                    "error": "telegram_chat_target_missing",
                    "where": "notify_channel_payment_success",
                    "fix": "Ensure Telegram runtime sync stores telegram_chat_id metadata or provider_user_id.",
                    "identity": identity,
                }

            delivery = _send_telegram_text(
                chat_id=delivery_target,
                text=message,
            )

        if not delivery.get("ok"):
            return {
                "ok": False,
                "error": delivery.get("error", "delivery_failed"),
                "where": delivery.get("where", "notify_channel_payment_success"),
                "fix": delivery.get("fix", "Check sender configuration."),
                "delivery_result": delivery,
                "message_preview": message,
                "account_id": acct,
                "channel_type": channel,
                "provider_user_id": delivery_target,
                "plan_code": code,
            }

        return {
            "ok": True,
            "account_id": acct,
            "channel_type": channel,
            "provider_user_id": delivery_target,
            "plan_code": code,
            "message_preview": message,
            "delivery_status": "sent",
            "delivery_result": delivery,
        }

    except Exception as e:
        return _fail(
            "notify_channel_payment_success",
            e,
            "Check channel identity lookup and sender delivery configuration.",
            {
                "account_id": acct,
                "channel_type": channel,
                "provider_user_id": provider_id or None,
                "plan_code": code,
            },
        )
