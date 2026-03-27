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

    digits = "".join(ch for ch in provider_id if ch.isdigit())
    if not digits:
        return None

    if channel == "whatsapp":
        return f"wa_{digits}@naijataxguide.local"

    if channel == "telegram":
        return f"tg_{digits}@naijataxguide.local"

    if channel == "web":
        return f"web_{digits}@naijataxguide.local"

    return None


def _fail(where: str, error: Any, fix: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = {
        "ok": False,
        "error": "channel_identity_service_failed",
        "where": where,
        "root_cause": repr(error),
        "fix": fix,
    }
    if extra:
        payload.update(extra)
    return payload


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

    try:
        referrer_account_id = get_referrer_account_id_from_code(ref_code) if ref_code else None
    except Exception as e:
        return _fail(
            "get_referrer_account_id_from_code",
            e,
            "Confirm referral_profiles exists and referral_code/account_id columns are correct.",
            {"referral_code": ref_code},
        )

    pseudo_email = _safe_email_from_channel(
        channel_type=channel,
        provider_user_id=provider_id,
    )

    # Keep this payload minimal to avoid schema mismatches on accounts.
    account_payload = {
        "provider": channel,
        "provider_user_id": provider_id,
        "email": pseudo_email,
    }

    try:
        created = sb.table("accounts").insert(account_payload).execute()
        rows = getattr(created, "data", None) or []
        if not rows:
            return _fail(
                "accounts.insert",
                "No rows returned from accounts insert",
                "Check accounts table defaults, RLS, and required columns.",
                {"account_payload": account_payload},
            )
        account = rows[0]
    except Exception as e:
        return _fail(
            "accounts.insert",
            e,
            "Check accounts schema. Required columns may differ from provider/provider_user_id/email only.",
            {"account_payload": account_payload},
        )

    channel_identity_payload = {
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

    try:
        sb.table("channel_identities").insert(channel_identity_payload).execute()
    except Exception as e:
        return _fail(
            "channel_identities.insert",
            e,
            "Check channel_identities schema and unique constraints.",
            {
                "account_id": account.get("account_id"),
                "channel_identity_payload": channel_identity_payload,
            },
        )

    if referrer_account_id:
        referral_payload = {
            "account_id": account["account_id"],
            "provisional_account_id": account["account_id"],
            "referral_code": ref_code,
            "referrer_account_id": referrer_account_id,
            "capture_channel": channel,
            "capture_url": None,
            "is_locked": True,
            "status": "linked",
        }
        try:
            sb.table("referral_attributions").insert(referral_payload).execute()
        except Exception as e:
            return _fail(
                "referral_attributions.insert",
                e,
                "Check referral_attributions schema and whether account_id/provisional_account_id types match.",
                {"referral_payload": referral_payload},
            )

    return {"ok": True, "account": account}


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

    try:
        existing = get_channel_identity(channel_type=channel, provider_user_id=provider_id)
        referrer_account_id = get_referrer_account_id_from_code(ref_code) if ref_code else None
    except Exception as e:
        return _fail(
            "create_or_update_channel_identity.precheck",
            e,
            "Check channel_identities read path and referral lookup path.",
        )

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

        try:
            updated = (
                sb.table("channel_identities")
                .update(payload)
                .eq("id", existing["id"])
                .execute()
            )
            rows = getattr(updated, "data", None) or []
            return {"ok": True, "channel_identity": rows[0] if rows else {**existing, **payload}}
        except Exception as e:
            return _fail(
                "channel_identities.update",
                e,
                "Check channel_identities schema and update permissions.",
                {"payload": payload, "existing_id": existing.get("id")},
            )

    if referrer_account_id:
        payload["referral_code"] = ref_code
        payload["referrer_account_id"] = referrer_account_id
        payload["referral_locked"] = True

    payload["first_seen_at"] = _now_iso()
    payload["is_verified"] = channel == "whatsapp"

    try:
        created = sb.table("channel_identities").insert(payload).execute()
        rows = getattr(created, "data", None) or []
        return {"ok": True, "channel_identity": rows[0] if rows else payload}
    except Exception as e:
        return _fail(
            "channel_identities.insert",
            e,
            "Check channel_identities schema and unique constraints.",
            {"payload": payload},
        )


def _touch_channel_identity(
    *,
    identity: Dict[str, Any],
    display_name: Optional[str] = None,
    referral_code: Optional[str] = None,
) -> Dict[str, Any]:
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
        try:
            referrer_account_id = get_referrer_account_id_from_code(incoming_ref)
        except Exception as e:
            return _fail(
                "_touch_channel_identity.referral_lookup",
                e,
                "Check referral lookup function and referral_profiles table.",
            )

        if referrer_account_id:
            update_payload["referral_code"] = incoming_ref
            update_payload["referrer_account_id"] = referrer_account_id
            update_payload["referral_locked"] = True

    try:
        updated = (
            sb.table("channel_identities")
            .update(update_payload)
            .eq("id", identity["id"])
            .execute()
        )
        rows = getattr(updated, "data", None) or []
        return {"ok": True, "channel_identity": rows[0] if rows else {**identity, **update_payload}}
    except Exception as e:
        return _fail(
            "_touch_channel_identity.update",
            e,
            "Check channel_identities update path.",
            {"update_payload": update_payload, "id": identity.get("id")},
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

    try:
        existing_identity = get_channel_identity(
            channel_type=channel,
            provider_user_id=provider_id,
        )
    except Exception as e:
        return _fail(
            "get_channel_identity",
            e,
            "Check channel_identities table and read access.",
            {"channel_type": channel, "provider_user_id": provider_id},
        )

    if existing_identity:
        try:
            account = get_account_by_account_id(existing_identity["account_id"])
        except Exception as e:
            return _fail(
                "get_account_by_account_id",
                e,
                "Check accounts table and account_id column.",
                {"account_id": existing_identity.get("account_id")},
            )

        if account:
            touched = _touch_channel_identity(
                identity=existing_identity,
                display_name=display_name,
                referral_code=referral_code,
            )
            if not touched.get("ok"):
                return touched

            return {
                "ok": True,
                "account": account,
                "channel_identity": touched.get("channel_identity") or existing_identity,
                "created": False,
            }

    try:
        existing_account = get_account_by_provider_identity(
            provider=channel,
            provider_user_id=provider_id,
        )
    except Exception as e:
        return _fail(
            "get_account_by_provider_identity",
            e,
            "Check accounts table provider/provider_user_id columns.",
            {"provider": channel, "provider_user_id": provider_id},
        )

    if existing_account:
        identity = get_channel_identity(channel_type=channel, provider_user_id=provider_id)
        if not identity:
            created_or_updated = create_or_update_channel_identity(
                account_id=existing_account["account_id"],
                channel_type=channel,
                provider_user_id=provider_id,
                display_name=display_name,
                referral_code=referral_code,
            )
            if not created_or_updated.get("ok"):
                return created_or_updated
            identity = created_or_updated.get("channel_identity")

        return {
            "ok": True,
            "account": existing_account,
            "channel_identity": identity,
            "created": False,
        }

    created_account = create_account_for_channel_identity(
        channel_type=channel,
        provider_user_id=provider_id,
        display_name=display_name,
        referral_code=referral_code,
    )
    if not created_account.get("ok"):
        return created_account

    account = created_account["account"]
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
