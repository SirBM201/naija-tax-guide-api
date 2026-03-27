from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase
from app.services.guest_access_service import get_referrer_account_id_from_code

DEFAULT_PROVIDER = os.getenv("DEFAULT_AUTH_PROVIDER", "channel")


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _safe_email_from_channel(
    *,
    channel_type: str,
    provider_user_id: str,
) -> Optional[str]:
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)
    if not provider_id:
        return None

    if channel == "whatsapp":
        digits = "".join(ch for ch in provider_id if ch.isdigit())
        if digits:
            return f"wa_{digits}@naijataxguide.local"

    if channel == "telegram":
        digits = "".join(ch for ch in provider_id if ch.isdigit())
        if digits:
            return f"tg_{digits}@naijataxguide.local"

    return None


def get_channel_identity(
    *,
    channel_type: str,
    provider_user_id: str,
) -> Optional[Dict[str, Any]]:
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)
    if not channel or not provider_id:
        return None

    sb = _sb()
    res = (
        sb.table("channel_identities")
        .select("*")
        .eq("channel_type", channel)
        .eq("provider_user_id", provider_id)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def get_account_by_account_id(account_id: str) -> Optional[Dict[str, Any]]:
    acct = _clean(account_id)
    if not acct:
        return None

    sb = _sb()
    res = (
        sb.table("accounts")
        .select("*")
        .eq("account_id", acct)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def get_account_by_provider_identity(
    *,
    provider: str,
    provider_user_id: str,
) -> Optional[Dict[str, Any]]:
    provider = _clean(provider).lower()
    provider_user_id = _clean(provider_user_id)
    if not provider or not provider_user_id:
        return None

    sb = _sb()
    res = (
        sb.table("accounts")
        .select("*")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def create_account_for_channel_identity(
    *,
    channel_type: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    referral_code: Optional[str] = None,
) -> Dict[str, Any]:
    sb = _sb()

    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)
    name = _clean(display_name) or None
    ref_code = _clean(referral_code) or None
    referrer_account_id = get_referrer_account_id_from_code(ref_code) if ref_code else None

    pseudo_email = _safe_email_from_channel(
        channel_type=channel,
        provider_user_id=provider_id,
    )

    payload = {
        "provider": channel,
        "provider_user_id": provider_id,
        "email": pseudo_email,
        "display_name": name,
        "full_name": name,
        "status": "active",
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
    }

    created = sb.table("accounts").insert(payload).execute()
    rows = getattr(created, "data", None) or []
    account = rows[0]

    sb.table("channel_identities").insert(
        {
            "account_id": account["account_id"],
            "channel_type": channel,
            "provider_user_id": provider_id,
            "is_verified": channel == "whatsapp",
            "referral_code": ref_code,
            "referrer_account_id": referrer_account_id,
            "referral_locked": bool(referrer_account_id),
            "first_seen_at": _now_iso(),
            "last_seen_at": _now_iso(),
            "metadata": {
                "display_name": name,
                "created_from": "channel_first_entry",
            },
        }
    ).execute()

    if referrer_account_id:
        sb.table("referral_attributions").insert(
            {
                "account_id": account["account_id"],
                "provisional_account_id": account["account_id"],
                "referral_code": ref_code,
                "referrer_account_id": referrer_account_id,
                "capture_channel": channel,
                "capture_url": None,
                "is_locked": True,
                "status": "linked",
            }
        ).execute()

    return account


def create_or_update_channel_identity(
    *,
    account_id: str,
    channel_type: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    referral_code: Optional[str] = None,
    guest_session_id: Optional[str] = None,
) -> Dict[str, Any]:
    sb = _sb()
    acct = _clean(account_id)
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)
    name = _clean(display_name) or None
    ref_code = _clean(referral_code) or None
    guest_id = _clean(guest_session_id) or None

    existing = get_channel_identity(channel_type=channel, provider_user_id=provider_id)
    referrer_account_id = get_referrer_account_id_from_code(ref_code) if ref_code else None

    payload = {
        "account_id": acct,
        "channel_type": channel,
        "provider_user_id": provider_id,
        "last_seen_at": _now_iso(),
        "guest_session_id": guest_id,
        "metadata": {
            "display_name": name,
        },
    }

    if existing:
        if not existing.get("referral_locked") and referrer_account_id:
            payload["referral_code"] = ref_code
            payload["referrer_account_id"] = referrer_account_id
            payload["referral_locked"] = True

        updated = (
            sb.table("channel_identities")
            .update(payload)
            .eq("id", existing["id"])
            .execute()
        )
        rows = getattr(updated, "data", None) or []
        return rows[0] if rows else {**existing, **payload}

    if referrer_account_id:
        payload["referral_code"] = ref_code
        payload["referrer_account_id"] = referrer_account_id
        payload["referral_locked"] = True

    payload["first_seen_at"] = _now_iso()
    payload["is_verified"] = channel == "whatsapp"

    created = sb.table("channel_identities").insert(payload).execute()
    rows = getattr(created, "data", None) or []
    return rows[0]


def _touch_channel_identity(
    *,
    identity: Dict[str, Any],
    display_name: Optional[str] = None,
    referral_code: Optional[str] = None,
) -> None:
    sb = _sb()
    update_payload: Dict[str, Any] = {
        "last_seen_at": _now_iso(),
    }

    name = _clean(display_name) or None
    if name:
        update_payload["metadata"] = {
            **(identity.get("metadata") or {}),
            "display_name": name,
        }

    incoming_ref = _clean(referral_code)
    if incoming_ref and not bool(identity.get("referral_locked")):
        referrer_account_id = get_referrer_account_id_from_code(incoming_ref)
        if referrer_account_id:
            update_payload["referral_code"] = incoming_ref
            update_payload["referrer_account_id"] = referrer_account_id
            update_payload["referral_locked"] = True

    (
        sb.table("channel_identities")
        .update(update_payload)
        .eq("id", identity["id"])
        .execute()
    )


def ensure_account_for_channel_identity(
    *,
    channel_type: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    referral_code: Optional[str] = None,
) -> Dict[str, Any]:
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)

    existing_identity = get_channel_identity(
        channel_type=channel,
        provider_user_id=provider_id,
    )
    if existing_identity:
        account = get_account_by_account_id(existing_identity["account_id"])
        if account:
            _touch_channel_identity(
                identity=existing_identity,
                display_name=display_name,
                referral_code=referral_code,
            )
            return {
                "ok": True,
                "account": account,
                "channel_identity": existing_identity,
                "created": False,
            }

    existing_account = get_account_by_provider_identity(
        provider=channel,
        provider_user_id=provider_id,
    )
    if existing_account:
        identity = get_channel_identity(channel_type=channel, provider_user_id=provider_id)
        if not identity:
            identity = create_or_update_channel_identity(
                account_id=existing_account["account_id"],
                channel_type=channel,
                provider_user_id=provider_id,
                display_name=display_name,
                referral_code=referral_code,
            )
        return {
            "ok": True,
            "account": existing_account,
            "channel_identity": identity,
            "created": False,
        }

    account = create_account_for_channel_identity(
        channel_type=channel,
        provider_user_id=provider_id,
        display_name=display_name,
        referral_code=referral_code,
    )
    identity = get_channel_identity(channel_type=channel, provider_user_id=provider_id)

    return {
        "ok": True,
        "account": account,
        "channel_identity": identity,
        "created": True,
    }


def initialize_channel_subscription_context(
    *,
    account_id: str,
    channel_type: str,
    provider_user_id: str,
    plan_code: str,
) -> Dict[str, Any]:
    return {
        "ok": True,
        "account_id": _clean(account_id),
        "channel_type": _clean(channel_type).lower(),
        "provider_user_id": _clean(provider_user_id),
        "plan_code": _clean(plan_code),
        "payment_flow": "paystack_link",
    }
