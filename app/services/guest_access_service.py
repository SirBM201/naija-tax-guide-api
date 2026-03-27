from __future__ import annotations

import hashlib
import os
import secrets
from typing import Any, Dict, Optional, Tuple

from flask import Request

from app.core.supabase_client import supabase

VISITOR_TOKEN_COOKIE_NAME = os.getenv("VISITOR_TOKEN_COOKIE_NAME", "ntg_visitor")
REFERRAL_FIRST_TOUCH_LOCK = os.getenv("REFERRAL_FIRST_TOUCH_LOCK", "1").strip() == "1"


def _sb():
    return supabase() if callable(supabase) else supabase


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _safe_trim(value: Any) -> str:
    return str(value or "").strip()


def _device_hash(request: Request) -> str:
    raw = "|".join(
        [
            _safe_trim(request.headers.get("User-Agent")),
            _safe_trim(request.headers.get("Accept-Language")),
            _safe_trim(request.headers.get("X-Forwarded-For") or request.remote_addr),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _extract_client_ip(request: Request) -> str:
    return _safe_trim(request.headers.get("X-Forwarded-For") or request.remote_addr)


def _extract_utm(args) -> Dict[str, Optional[str]]:
    return {
        "utm_source": _safe_trim(args.get("utm_source")) or None,
        "utm_medium": _safe_trim(args.get("utm_medium")) or None,
        "utm_campaign": _safe_trim(args.get("utm_campaign")) or None,
    }


def generate_visitor_token() -> str:
    return secrets.token_urlsafe(32)


def get_or_create_visitor_token(request: Request) -> Tuple[str, bool]:
    existing = _safe_trim(request.cookies.get(VISITOR_TOKEN_COOKIE_NAME))
    if existing:
        return existing, False
    return generate_visitor_token(), True


def get_referrer_account_id_from_code(referral_code: str) -> Optional[str]:
    code = _safe_trim(referral_code)
    if not code:
        return None

    sb = _sb()
    res = (
        sb.table("referral_profiles")
        .select("account_id, referral_code")
        .eq("referral_code", code)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    if not rows:
        return None
    return rows[0].get("account_id")


def get_guest_session_by_token(visitor_token: str) -> Optional[Dict[str, Any]]:
    token = _safe_trim(visitor_token)
    if not token:
        return None

    sb = _sb()
    res = (
        sb.table("guest_sessions")
        .select("*")
        .eq("visitor_token", token)
        .limit(1)
        .execute()
    )
    rows = getattr(res, "data", None) or []
    return rows[0] if rows else None


def create_guest_session(
    *,
    visitor_token: str,
    request: Request,
    entry_channel: str = "web",
    referral_code: Optional[str] = None,
) -> Dict[str, Any]:
    sb = _sb()
    referrer_account_id = get_referrer_account_id_from_code(referral_code or "")
    locked = bool(referrer_account_id and REFERRAL_FIRST_TOUCH_LOCK)

    payload = {
        "visitor_token": visitor_token,
        "entry_channel": entry_channel,
        "first_seen_at": _now_iso(),
        "last_seen_at": _now_iso(),
        "ip_address": _extract_client_ip(request),
        "user_agent": _safe_trim(request.headers.get("User-Agent")) or None,
        "device_hash": _device_hash(request),
        "referral_code": _safe_trim(referral_code) or None,
        "referrer_account_id": referrer_account_id,
        "referral_locked": locked,
        "landing_path": _safe_trim(request.path) or None,
        "landing_url": _safe_trim(request.url) or None,
        **_extract_utm(request.args),
    }

    created = sb.table("guest_sessions").insert(payload).execute()
    rows = getattr(created, "data", None) or []
    session = rows[0] if rows else payload

    if referrer_account_id:
        sb.table("referral_attributions").insert(
            {
                "guest_session_id": session.get("guest_session_id"),
                "referral_code": _safe_trim(referral_code),
                "referrer_account_id": referrer_account_id,
                "capture_channel": entry_channel,
                "capture_url": _safe_trim(request.url) or None,
                "is_locked": locked,
                "status": "captured",
            }
        ).execute()

    sb.table("guest_session_events").insert(
        {
            "guest_session_id": session.get("guest_session_id"),
            "event_type": "guest_session_created",
            "payload": {
                "entry_channel": entry_channel,
                "referral_code": _safe_trim(referral_code) or None,
            },
        }
    ).execute()

    return session


def touch_guest_session(
    *,
    session: Dict[str, Any],
    request: Request,
) -> Dict[str, Any]:
    sb = _sb()
    guest_session_id = session.get("guest_session_id")
    if not guest_session_id:
        return session

    update_payload = {
        "last_seen_at": _now_iso(),
        "ip_address": _extract_client_ip(request),
        "user_agent": _safe_trim(request.headers.get("User-Agent")) or None,
        "landing_path": _safe_trim(request.path) or None,
        "landing_url": _safe_trim(request.url) or None,
    }

    current_locked = bool(session.get("referral_locked"))
    existing_ref_code = _safe_trim(session.get("referral_code"))
    incoming_ref = _safe_trim(request.args.get("ref"))

    if (
        not current_locked
        and not existing_ref_code
        and incoming_ref
    ):
        referrer_account_id = get_referrer_account_id_from_code(incoming_ref)
        if referrer_account_id:
            update_payload["referral_code"] = incoming_ref
            update_payload["referrer_account_id"] = referrer_account_id
            update_payload["referral_locked"] = REFERRAL_FIRST_TOUCH_LOCK

            sb.table("referral_attributions").insert(
                {
                    "guest_session_id": guest_session_id,
                    "referral_code": incoming_ref,
                    "referrer_account_id": referrer_account_id,
                    "capture_channel": _safe_trim(session.get("entry_channel")) or "web",
                    "capture_url": _safe_trim(request.url) or None,
                    "is_locked": REFERRAL_FIRST_TOUCH_LOCK,
                    "status": "captured",
                }
            ).execute()

    updated = (
        sb.table("guest_sessions")
        .update(update_payload)
        .eq("guest_session_id", guest_session_id)
        .execute()
    )
    rows = getattr(updated, "data", None) or []
    return rows[0] if rows else {**session, **update_payload}


def ensure_guest_session(request: Request) -> Tuple[Dict[str, Any], str, bool]:
    visitor_token, is_new = get_or_create_visitor_token(request)
    session = get_guest_session_by_token(visitor_token)

    if session:
        touched = touch_guest_session(session=session, request=request)
        return touched, visitor_token, is_new

    created = create_guest_session(
        visitor_token=visitor_token,
        request=request,
        entry_channel="web",
        referral_code=_safe_trim(request.args.get("ref")) or None,
    )
    return created, visitor_token, is_new


def attach_guest_session_to_account(
    *,
    visitor_token: str,
    account_id: str,
) -> Dict[str, Any]:
    token = _safe_trim(visitor_token)
    acct = _safe_trim(account_id)
    if not token or not acct:
        return {"ok": False, "error": "missing_visitor_token_or_account_id"}

    session = get_guest_session_by_token(token)
    if not session:
        return {"ok": False, "error": "guest_session_not_found"}

    sb = _sb()
    updated = (
        sb.table("guest_sessions")
        .update({"provisional_account_id": acct, "last_seen_at": _now_iso()})
        .eq("guest_session_id", session["guest_session_id"])
        .execute()
    )
    rows = getattr(updated, "data", None) or []

    sb.table("referral_attributions").update(
        {
            "account_id": acct,
            "provisional_account_id": acct,
            "status": "linked",
        }
    ).eq("guest_session_id", session["guest_session_id"]).execute()

    sb.table("guest_session_events").insert(
        {
            "guest_session_id": session["guest_session_id"],
            "event_type": "guest_session_linked_to_account",
            "payload": {"account_id": acct},
        }
    ).execute()

    return {"ok": True, "session": rows[0] if rows else session}
