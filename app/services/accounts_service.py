# app/services/accounts_service.py
from __future__ import annotations

from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timezone
import uuid

from app.core.supabase_client import supabase


# ---------------------------------------------------------
# Time helpers
# ---------------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_utc().isoformat()


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def _is_active_from_expiry(expiry: Optional[datetime]) -> bool:
    if not expiry:
        return False
    return expiry > _now_utc()


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except Exception:
        return False


# ---------------------------------------------------------
# Provider normalization (must match DB constraint list)
# IMPORTANT: your DB currently shows provider check includes:
#   wa, web, tg, ig, email
# If you haven't added msgr yet, leave it out for now.
# ---------------------------------------------------------
ALLOWED_PROVIDERS = {"wa", "tg", "ig", "email", "web"}  # add "msgr" only AFTER DB constraint updated

PROVIDER_ALIASES = {
    # WhatsApp
    "wa": "wa",
    "whatsapp": "wa",
    "waba": "wa",
    # Telegram
    "tg": "tg",
    "telegram": "tg",
    # Instagram
    "ig": "ig",
    "instagram": "ig",
    "instagram_dm": "ig",
    "insta": "ig",
    # Email
    "email": "email",
    "mail": "email",
    # Web
    "web": "web",
    "website": "web",
    # Messenger (keep alias, but will fail validation until DB supports msgr)
    "msgr": "msgr",
    "messenger": "msgr",
    "facebook_messenger": "msgr",
    "fb_messenger": "msgr",
    "facebook messenger": "msgr",
}


def _norm_provider(provider: str) -> str:
    p = (provider or "").strip().lower()
    return PROVIDER_ALIASES.get(p, p)


def _validate_provider_and_id(provider: str, provider_user_id: str) -> Optional[str]:
    provider = _norm_provider(provider)
    if provider not in ALLOWED_PROVIDERS:
        return f"provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}"
    if not provider_user_id:
        return "provider_user_id required"

    if provider == "email":
        v = provider_user_id.strip().lower()
        if "@" not in v or "." not in v:
            return "provider_user_id must be a valid email address for provider=email"

    return None


# ---------------------------------------------------------
# Accounts: upsert / lookup
# ---------------------------------------------------------
def upsert_account(
    *,
    provider: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
    phone_e164: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates or updates an account row.

    - Keeps your current style: returns {"ok": True, "account": row}
    - phone_e164 is OPTIONAL and safe:
        If accounts table doesn't have the column yet, it retries without it.
    """
    provider = _norm_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    err = _validate_provider_and_id(provider, provider_user_id)
    if err:
        return {"ok": False, "error": err}

    payload: Dict[str, Any] = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "display_name": (display_name or None),
        "phone": (phone or None),
        "updated_at": _now_iso(),
    }

    # include phone_e164 only if provided
    if phone_e164:
        payload["phone_e164"] = phone_e164

    try:
        res = supabase().table("accounts").upsert(
            payload,
            on_conflict="provider,provider_user_id",
            returning="representation",
        ).execute()
        row = (res.data or [None])[0]
        return {"ok": True, "account": row}
    except Exception as e:
        # If accounts table doesn't have phone_e164, retry without it
        msg = str(e)
        if "phone_e164" in msg and "does not exist" in msg:
            payload.pop("phone_e164", None)
            try:
                res2 = supabase().table("accounts").upsert(
                    payload,
                    on_conflict="provider,provider_user_id",
                    returning="representation",
                ).execute()
                row2 = (res2.data or [None])[0]
                return {"ok": True, "account": row2, "note": "phone_e164 ignored (column missing)"}
            except Exception as e2:
                return {"ok": False, "error": f"DB error: {str(e2)}"}
        return {"ok": False, "error": f"DB error: {msg}"}


def lookup_account(
    *,
    provider: str,
    provider_user_id: str,
) -> Dict[str, Any]:
    provider = _norm_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    err = _validate_provider_and_id(provider, provider_user_id)
    if err:
        return {"ok": False, "error": err}

    try:
        res = (
            supabase()
            .table("accounts")
            .select("id,provider,provider_user_id,auth_user_id,display_name,phone,updated_at,created_at")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return {"ok": False, "error": f"DB error: {str(e)}"}

    row = (res.data or [None])[0]
    if not row:
        return {"ok": True, "found": False, "linked": False, "auth_user_id": None, "account": None}

    auth_user_id = row.get("auth_user_id")
    return {
        "ok": True,
        "found": True,
        "linked": bool(auth_user_id),
        "auth_user_id": auth_user_id,
        "account": row,
    }


def ensure_account_id(
    *,
    provider: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
    phone_e164: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convenience for web_auth and channel handlers.

    Returns:
      { ok: bool, account_id: str|None, created: bool, error?: str, account?: dict }
    """
    provider = _norm_provider(provider)
    provider_user_id = (provider_user_id or "").strip()

    existing = lookup_account(provider=provider, provider_user_id=provider_user_id)
    if not existing.get("ok"):
        return {"ok": False, "account_id": None, "created": False, "error": existing.get("error")}

    if existing.get("found") and existing.get("account"):
        return {"ok": True, "account_id": existing["account"]["id"], "created": False, "account": existing["account"]}

    created = upsert_account(
        provider=provider,
        provider_user_id=provider_user_id,
        display_name=display_name,
        phone=phone,
        phone_e164=phone_e164,
    )
    if not created.get("ok") or not created.get("account"):
        return {"ok": False, "account_id": None, "created": False, "error": created.get("error")}

    return {"ok": True, "account_id": created["account"]["id"], "created": True, "account": created["account"]}


# ---------------------------------------------------------
# Plan status: YOUR DB (public.subscriptions) FIRST
# ---------------------------------------------------------
def _plan_from_subscriptions_table(auth_user_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        res = (
            supabase()
            .table("subscriptions")
            .select("user_id,plan,status,start_at,end_at,updated_at,id")
            .eq("user_id", auth_user_id)
            .order("updated_at", desc=True)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return None, str(e)

    row = (res.data or [None])[0]
    if not row:
        return None, None

    end_dt = _parse_dt(row.get("end_at"))
    status = (row.get("status") or "").strip().lower() or None

    active = False
    if end_dt and end_dt > _now_utc():
        active = True
    elif status in ("active", "paid", "success"):
        active = True

    return (
        {
            "known": True,
            "source": "subscriptions",
            "plan": row.get("plan"),
            "status": row.get("status"),
            "plan_expiry": end_dt.isoformat() if end_dt else None,
            "is_active": bool(active),
        },
        None,
    )


def _try_fetch_plan_from_table_guess(table_name: str, auth_user_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    auth_err = None
    user_err = None

    try:
        res = (
            supabase()
            .table(table_name)
            .select("*")
            .eq("auth_user_id", auth_user_id)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        row = (res.data or [None])[0]
        if row:
            expiry_dt = _parse_dt(
                row.get("end_at")
                or row.get("plan_expiry")
                or row.get("expires_at")
                or row.get("current_period_end")
            )
            active = bool(row.get("is_active")) if isinstance(row.get("is_active"), bool) else _is_active_from_expiry(expiry_dt)
            return (
                {
                    "known": True,
                    "source": table_name,
                    "plan": row.get("plan") or row.get("tier") or row.get("plan_code"),
                    "status": row.get("status"),
                    "plan_expiry": expiry_dt.isoformat() if expiry_dt else None,
                    "is_active": bool(active),
                },
                None,
            )
    except Exception as e:
        auth_err = str(e)

    try:
        res2 = (
            supabase()
            .table(table_name)
            .select("*")
            .eq("user_id", auth_user_id)
            .order("updated_at", desc=True)
            .limit(1)
            .execute()
        )
        row2 = (res2.data or [None])[0]
        if row2:
            expiry_dt = _parse_dt(row2.get("end_at") or row2.get("expires_at") or row2.get("plan_expiry"))
            active = _is_active_from_expiry(expiry_dt)
            return (
                {
                    "known": True,
                    "source": table_name,
                    "plan": row2.get("plan") or row2.get("tier") or row2.get("plan_code"),
                    "status": row2.get("status"),
                    "plan_expiry": expiry_dt.isoformat() if expiry_dt else None,
                    "is_active": bool(active),
                },
                None,
            )
    except Exception as e:
        user_err = str(e)

    return None, (auth_err or user_err)


def get_plan_status(auth_user_id: Optional[str]) -> Dict[str, Any]:
    auth_user_id = (auth_user_id or "").strip()
    if not auth_user_id:
        return {"ok": True, "known": False, "is_active": False, "plan": None, "status": None, "plan_expiry": None}

    plan_obj, err = _plan_from_subscriptions_table(auth_user_id)
    if err is None and plan_obj:
        return {"ok": True, **plan_obj}

    debug_errors: List[Dict[str, str]] = []
    if err:
        debug_errors.append({"table": "subscriptions", "error": err})

    candidates = ["user_subscriptions", "user_plans", "plans"]
    for t in candidates:
        obj, e = _try_fetch_plan_from_table_guess(t, auth_user_id)
        if obj:
            return {"ok": True, **obj}
        if e:
            debug_errors.append({"table": t, "error": e})

    return {
        "ok": True,
        "known": False,
        "is_active": False,
        "plan": None,
        "status": None,
        "plan_expiry": None,
        "notes": "No subscription record found.",
        "debug_errors": debug_errors[:2],
    }
