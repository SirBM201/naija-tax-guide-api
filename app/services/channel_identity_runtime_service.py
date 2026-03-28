from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.supabase_client import supabase


def _sb():
    return supabase() if callable(supabase) else supabase


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fail(where: str, error: Any, fix: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = {
        "ok": False,
        "error": "channel_identity_runtime_service_failed",
        "where": where,
        "root_cause": repr(error),
        "fix": fix,
    }
    if extra:
        payload.update(extra)
    return payload


def get_channel_identity_by_account(
    *,
    account_id: str,
    channel_type: str,
) -> Optional[Dict[str, Any]]:
    acct = _clean(account_id)
    channel = _clean(channel_type).lower()
    if not acct or not channel:
        return None

    res = (
        _sb()
        .table("channel_identities")
        .select("*")
        .eq("account_id", acct)
        .eq("channel_type", channel)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def get_channel_identity_by_provider(
    *,
    channel_type: str,
    provider_user_id: str,
) -> Optional[Dict[str, Any]]:
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)
    if not channel or not provider_id:
        return None

    res = (
        _sb()
        .table("channel_identities")
        .select("*")
        .eq("channel_type", channel)
        .eq("provider_user_id", provider_id)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def touch_channel_identity_runtime(
    *,
    identity_id: str,
    display_name: Optional[str] = None,
    metadata_patch: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    identity_pk = _clean(identity_id)
    if not identity_pk:
        return {
            "ok": False,
            "error": "identity_id_required",
            "where": "touch_channel_identity_runtime",
            "fix": "Pass a valid channel_identities.id value.",
        }

    try:
        current_res = (
            _sb()
            .table("channel_identities")
            .select("*")
            .eq("id", identity_pk)
            .limit(1)
            .execute()
        )
        rows = getattr(current_res, "data", None) or []
        if not rows:
            return {
                "ok": False,
                "error": "channel_identity_not_found",
                "where": "touch_channel_identity_runtime",
                "fix": "Confirm the channel identity row exists before touching it.",
                "identity_id": identity_pk,
            }

        current = rows[0]
        current_md = current.get("metadata") or {}
        if not isinstance(current_md, dict):
            current_md = {}

        patch = metadata_patch or {}
        if not isinstance(patch, dict):
            patch = {}

        if _clean(display_name):
            patch["display_name"] = _clean(display_name)

        merged_md = {
            **current_md,
            **patch,
        }

        updated = (
            _sb()
            .table("channel_identities")
            .update(
                {
                    "last_seen_at": _now_iso(),
                    "metadata": merged_md,
                }
            )
            .eq("id", identity_pk)
            .execute()
        )
        updated_rows = getattr(updated, "data", None) or []
        return {
            "ok": True,
            "channel_identity": updated_rows[0] if updated_rows else {**current, "metadata": merged_md},
        }
    except Exception as e:
        return _fail(
            "touch_channel_identity_runtime",
            e,
            "Check channel_identities read/update path and metadata column type.",
            {"identity_id": identity_pk},
        )


def sync_channel_identity_runtime(
    *,
    account_id: str,
    channel_type: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    metadata_patch: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Main runtime auto-correct entry point.

    Use this after receiving a real inbound WhatsApp/Telegram message.
    It ensures the linked account's channel identity keeps the latest
    real provider_user_id (e.g. Telegram message.chat.id).
    """
    acct = _clean(account_id)
    channel = _clean(channel_type).lower()
    provider_id = _clean(provider_user_id)
    name = _clean(display_name)
    patch = metadata_patch or {}
    if not isinstance(patch, dict):
        patch = {}

    if not acct:
        return {
            "ok": False,
            "error": "account_id_required",
            "where": "sync_channel_identity_runtime",
            "fix": "Pass a valid linked account_id.",
        }

    if channel not in {"telegram", "whatsapp"}:
        return {
            "ok": False,
            "error": "invalid_channel_type",
            "where": "sync_channel_identity_runtime",
            "fix": "Use telegram or whatsapp.",
            "channel_type": channel,
        }

    if not provider_id:
        return {
            "ok": False,
            "error": "provider_user_id_required",
            "where": "sync_channel_identity_runtime",
            "fix": "Pass the real inbound provider_user_id (for Telegram, message.chat.id).",
        }

    try:
        by_account = get_channel_identity_by_account(
            account_id=acct,
            channel_type=channel,
        )
        by_provider = get_channel_identity_by_provider(
            channel_type=channel,
            provider_user_id=provider_id,
        )

        if by_provider and _clean(by_provider.get("account_id")) == acct:
            return touch_channel_identity_runtime(
                identity_id=_clean(by_provider.get("id")),
                display_name=name or None,
                metadata_patch={
                    **patch,
                    "runtime_seen": True,
                    "last_runtime_provider_user_id": provider_id,
                },
            )

        if by_provider and _clean(by_provider.get("account_id")) != acct:
            return {
                "ok": False,
                "error": "provider_user_id_already_linked_to_other_account",
                "where": "sync_channel_identity_runtime",
                "fix": "Investigate duplicate or crossed channel linkage before auto-correcting.",
                "requested_account_id": acct,
                "existing_account_id": _clean(by_provider.get("account_id")),
                "channel_type": channel,
                "provider_user_id": provider_id,
            }

        if by_account:
            old_provider_user_id = _clean(by_account.get("provider_user_id"))
            current_md = by_account.get("metadata") or {}
            if not isinstance(current_md, dict):
                current_md = {}

            merged_md = {
                **current_md,
                **patch,
                "runtime_seen": True,
                "last_runtime_provider_user_id": provider_id,
            }

            if name:
                merged_md["display_name"] = name

            if old_provider_user_id != provider_id:
                merged_md["provider_user_id_autocorrected"] = True
                merged_md["previous_provider_user_id"] = old_provider_user_id
                merged_md["provider_user_id_corrected_at"] = _now_iso()

            updated = (
                _sb()
                .table("channel_identities")
                .update(
                    {
                        "provider_user_id": provider_id,
                        "last_seen_at": _now_iso(),
                        "metadata": merged_md,
                    }
                )
                .eq("id", by_account["id"])
                .execute()
            )
            rows = getattr(updated, "data", None) or []

            return {
                "ok": True,
                "autocorrected": old_provider_user_id != provider_id,
                "old_provider_user_id": old_provider_user_id,
                "new_provider_user_id": provider_id,
                "channel_identity": rows[0] if rows else {**by_account, "provider_user_id": provider_id, "metadata": merged_md},
            }

        created_payload = {
            "account_id": acct,
            "channel_type": channel,
            "provider_user_id": provider_id,
            "is_verified": channel == "whatsapp",
            "first_seen_at": _now_iso(),
            "last_seen_at": _now_iso(),
            "metadata": {
                **patch,
                "runtime_seen": True,
                "last_runtime_provider_user_id": provider_id,
                "display_name": name or None,
                "created_from": "runtime_autocorrect_service",
            },
        }

        created = _sb().table("channel_identities").insert(created_payload).execute()
        created_rows = getattr(created, "data", None) or []

        return {
            "ok": True,
            "created": True,
            "autocorrected": False,
            "channel_identity": created_rows[0] if created_rows else created_payload,
        }

    except Exception as e:
        return _fail(
            "sync_channel_identity_runtime",
            e,
            "Check channel_identities uniqueness, metadata type, and runtime account linkage flow.",
            {
                "account_id": acct,
                "channel_type": channel,
                "provider_user_id": provider_id,
            },
        )
