from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase
from app.services.guest_access_service import get_referrer_account_id_from_code
from app.services.paystack_service import initialize_transaction


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
        safe = provider_id.replace("@", "_").replace(" ", "_")
        digits = safe

    if channel == "whatsapp":
        return f"wa_{digits}@naijataxguide.local"
    if channel == "telegram":
        return f"tg_{digits}@naijataxguide.local"
    if channel == "web":
        return f"web_{digits}@naijataxguide.local"

    return f"channel_{digits}@naijataxguide.local"


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


def get_account_by_channel_pseudo_identity(
    *,
    pseudo_email: str,
) -> Optional[Dict[str, Any]]:
    email = _clean(pseudo_email)
    if not email:
        return None

    sb = _sb()
    res = (
        sb.table("accounts")
        .select("*")
        .eq("provider", "web")
        .eq("provider_user_id", email)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def get_plan_by_code(plan_code: str) -> Optional[Dict[str, Any]]:
    code = _clean(plan_code)
    if not code:
        return None

    sb = _sb()
    res = (
        sb.table("plans")
        .select("*")
        .eq("plan_code", code)
        .eq("active", True)
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

    account_payload = {
        "provider": "web",
        "provider_user_id": pseudo_email,
        "email": pseudo_email,
    }

    try:
        existing_account = get_account_by_channel_pseudo_identity(pseudo_email=pseudo_email or "")
        if existing_account:
            account = existing_account
        else:
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
            "Check accounts schema. provider must remain an allowed value. This implementation uses provider='web' and stores real channel identity in channel_identities.",
            {"account_payload": account_payload},
        )

    existing_identity = get_channel_identity(
        channel_type=channel,
        provider_user_id=provider_id,
    )

    if existing_identity:
        return {
            "ok": True,
            "account": account,
            "channel_identity": existing_identity,
            "created": False,
        }

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
            "pseudo_email": pseudo_email,
        },
    }

    try:
        created_identity = sb.table("channel_identities").insert(channel_identity_payload).execute()
        identity_rows = getattr(created_identity, "data", None) or []
        identity = identity_rows[0] if identity_rows else channel_identity_payload
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

    return {
        "ok": True,
        "account": account,
        "channel_identity": identity,
        "created": True,
    }


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

    pseudo_email = _safe_email_from_channel(
        channel_type=channel,
        provider_user_id=provider_id,
    )

    try:
        existing_account = get_account_by_channel_pseudo_identity(
            pseudo_email=pseudo_email or ""
        )
    except Exception as e:
        return _fail(
            "get_account_by_channel_pseudo_identity",
            e,
            "Check accounts table provider/provider_user_id columns.",
            {"pseudo_email": pseudo_email},
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
    identity = created_account.get("channel_identity") or get_channel_identity(
        channel_type=channel,
        provider_user_id=provider_id,
    )

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
    acct = _clean(account_id)
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)
    code = _clean(plan_code)

    try:
        account = get_account_by_account_id(acct)
        if not account:
            return {
                "ok": False,
                "error": "account_not_found",
                "where": "get_account_by_account_id",
                "fix": "Pass a valid account_id created through /api/channel/ensure-account.",
            }

        plan = get_plan_by_code(code)
        if not plan:
            return {
                "ok": False,
                "error": "plan_not_found",
                "where": "get_plan_by_code",
                "fix": "Use a valid plan_code from the plans table.",
                "plan_code": code,
            }

        email = _clean(account.get("email"))
        price_major = plan.get("price")
        try:
            amount_kobo = int(float(price_major) * 100)
        except Exception:
            amount_kobo = 0

        if not email:
            return {
                "ok": False,
                "error": "account_email_missing",
                "where": "initialize_channel_subscription_context",
                "fix": "Ensure the canonical account has an email value before payment initialization.",
                "account_id": acct,
            }

        if amount_kobo <= 0:
            return {
                "ok": False,
                "error": "invalid_plan_amount",
                "where": "initialize_channel_subscription_context",
                "fix": "Ensure the plans table contains a positive numeric price value for this plan.",
                "plan_code": code,
                "price": price_major,
            }

        paystack_resp = initialize_transaction(
            email=email,
            amount_kobo=amount_kobo,
            metadata={
                "product": "naija_tax_guide",
                "plan_code": code,
                "account_id": acct,
                "channel_type": channel,
                "provider_user_id": provider_id,
            },
        )

        return {
            "ok": True,
            "account_id": acct,
            "channel_type": channel,
            "provider_user_id": provider_id,
            "plan_code": code,
            "payment_flow": "paystack_link",
            "authorization_url": paystack_resp.get("authorization_url"),
            "access_code": paystack_resp.get("access_code"),
            "reference": paystack_resp.get("reference"),
        }

    except Exception as e:
        return _fail(
            "initialize_channel_subscription_context",
            e,
            "Check plans table shape and paystack initialize_transaction service signature.",
            {
                "account_id": acct,
                "channel_type": channel,
                "provider_user_id": provider_id,
                "plan_code": code,
            },
        )
