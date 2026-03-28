from __future__ import annotations

import os
from typing import Any, Dict, Optional

import requests

from app.services.channel_identity_service import initialize_channel_subscription_context


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _fail(where: str, error: Any, fix: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = {
        "ok": False,
        "error": "channel_payment_delivery_failed",
        "where": where,
        "root_cause": repr(error),
        "fix": fix,
    }
    if extra:
        payload.update(extra)
    return payload


def _build_payment_message(
    *,
    plan_code: str,
    authorization_url: str,
    reference: str,
) -> str:
    return (
        f"Your Naija Tax Guide payment link is ready.\n\n"
        f"Plan: {plan_code}\n"
        f"Reference: {reference}\n"
        f"Pay here: {authorization_url}\n\n"
        f"Complete the payment and your subscription will activate automatically."
    )


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
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        data = {}
        try:
            data = resp.json()
        except Exception:
            data = {"raw_text": resp.text}

        if resp.status_code >= 400:
            return {
                "ok": False,
                "error": "whatsapp_send_failed",
                "where": "_send_whatsapp_text",
                "fix": "Check WhatsApp Cloud API credentials, recipient number format, and business account permissions.",
                "status_code": resp.status_code,
                "response": data,
                "phone_number": phone_number,
            }

        return {
            "ok": True,
            "channel_type": "whatsapp",
            "delivery_response": data,
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
        resp = requests.post(url, json=payload, timeout=30)
        data = {}
        try:
            data = resp.json()
        except Exception:
            data = {"raw_text": resp.text}

        if resp.status_code >= 400 or not data.get("ok", False):
            return {
                "ok": False,
                "error": "telegram_send_failed",
                "where": "_send_telegram_text",
                "fix": "Check TELEGRAM_BOT_TOKEN, bot permissions, and whether the chat has started the bot.",
                "status_code": resp.status_code,
                "response": data,
                "chat_id": chat_id,
            }

        return {
            "ok": True,
            "channel_type": "telegram",
            "delivery_response": data,
        }
    except Exception as e:
        return _fail(
            "_send_telegram_text",
            e,
            "Check outbound internet access and Telegram env configuration.",
            {"chat_id": chat_id},
        )


def deliver_channel_payment_link(
    *,
    account_id: str,
    channel_type: str,
    provider_user_id: str,
    plan_code: str,
) -> Dict[str, Any]:
    acct = _clean(account_id)
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)
    code = _clean(plan_code)

    init_result = initialize_channel_subscription_context(
        account_id=acct,
        channel_type=channel,
        provider_user_id=provider_id,
        plan_code=code,
    )

    if not init_result.get("ok"):
        return init_result

    authorization_url = _clean(init_result.get("authorization_url"))
    reference = _clean(init_result.get("reference"))

    if not authorization_url or not reference:
        return {
            "ok": False,
            "error": "payment_link_missing",
            "where": "deliver_channel_payment_link",
            "fix": "Ensure initialize_channel_subscription_context returns authorization_url and reference.",
            "init_result": init_result,
        }

    message = _build_payment_message(
        plan_code=code,
        authorization_url=authorization_url,
        reference=reference,
    )

    if channel == "whatsapp":
        delivery = _send_whatsapp_text(
            phone_number=provider_id,
            text=message,
        )
    elif channel == "telegram":
        delivery = _send_telegram_text(
            chat_id=provider_id,
            text=message,
        )
    else:
        return {
            "ok": False,
            "error": "unsupported_delivery_channel",
            "where": "deliver_channel_payment_link",
            "fix": "Automatic payment-link delivery currently supports whatsapp and telegram only.",
            "channel_type": channel,
        }

    if not delivery.get("ok"):
        return {
            "ok": False,
            "error": delivery.get("error", "delivery_failed"),
            "where": delivery.get("where", "deliver_channel_payment_link"),
            "fix": delivery.get("fix", "Check sender configuration."),
            "delivery_result": delivery,
            "authorization_url": authorization_url,
            "reference": reference,
            "message_preview": message,
        }

    return {
        "ok": True,
        "account_id": acct,
        "channel_type": channel,
        "provider_user_id": provider_id,
        "plan_code": code,
        "payment_flow": "paystack_link",
        "authorization_url": authorization_url,
        "reference": reference,
        "message_preview": message,
        "delivery_status": "sent",
        "delivery_result": delivery,
    }
