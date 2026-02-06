from __future__ import annotations

from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone

from app.core.supabase_client import supabase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value: Any) -> Optional[datetime]:
    """
    Best-effort parse for timestamps that might come as:
    - ISO string
    - datetime
    - None
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            # Handles: "2026-02-06T14:03:31.703289+00:00"
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def _is_active_from_expiry(expiry: Optional[datetime]) -> bool:
    if not expiry:
        return False
    return expiry > datetime.now(timezone.utc)


def upsert_account(
    *,
    provider: str,
    provider_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Creates or updates an account row WITHOUT auth_user_id (pre-link state).
    Used when a message arrives before linking.
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg"):
        return {"ok": False, "error": "provider must be wa or tg"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id required"}

    payload = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "display_name": display_name,
        "phone": phone,
        "updated_at": _now_iso(),
    }

    try:
        res = (
            supabase()
            .table("accounts")
            .upsert(payload, on_conflict="provider,provider_user_id")
            .select("*")
            .execute()
        )
    except Exception as e:
        return {"ok": False, "error": f"DB error: {str(e)}"}

    row = (res.data or [None])[0]
    return {"ok": True, "account": row}


def upsert_account_link(
    *,
    provider: str,
    provider_user_id: str,
    auth_user_id: str,
    display_name: Optional[str] = None,
    phone: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Upserts an account row AND binds it to auth_user_id (linked state).
    Called after consume_link_token succeeds.
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()
    auth_user_id = (auth_user_id or "").strip()

    if provider not in ("wa", "tg"):
        return {"ok": False, "error": "provider must be wa or tg"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id required"}
    if not auth_user_id:
        return {"ok": False, "error": "auth_user_id required"}

    payload = {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "auth_user_id": auth_user_id,
        "display_name": display_name,
        "phone": phone,
        "updated_at": _now_iso(),
    }

    try:
        res = (
            supabase()
            .table("accounts")
            .upsert(payload, on_conflict="provider,provider_user_id")
            .select("*")
            .execute()
        )
    except Exception as e:
        return {"ok": False, "error": f"DB error: {str(e)}"}

    row = (res.data or [None])[0]
    return {"ok": True, "account": row}


def lookup_account(
    *,
    provider: str,
    provider_user_id: str,
) -> Dict[str, Any]:
    """
    Returns mapping from (provider, provider_user_id) -> auth_user_id (if linked)
    """
    provider = (provider or "").strip().lower()
    provider_user_id = (provider_user_id or "").strip()

    if provider not in ("wa", "tg"):
        return {"ok": False, "error": "provider must be wa or tg"}
    if not provider_user_id:
        return {"ok": False, "error": "provider_user_id required"}

    try:
        res = (
            supabase()
            .table("accounts")
            .select("provider,provider_user_id,auth_user_id,display_name,phone,updated_at,created_at")
            .eq("provider", provider)
            .eq("provider_user_id", provider_user_id)
            .limit(1)
            .execute()
        )
    except Exception as e:
        return {"ok": False, "error": f"DB error: {str(e)}"}

    row = (res.data or [None])[0]
    if not row:
        return {"ok": True, "found": False, "linked": False, "account": None}

    auth_user_id = row.get("auth_user_id")
    return {
        "ok": True,
        "found": True,
        "linked": bool(auth_user_id),
        "auth_user_id": auth_user_id,
        "account": row,
    }


def _try_fetch_plan_from_table(table_name: str, auth_user_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Tries to load the newest subscription record for a user from a given table.
    Returns (plan_dict, error_string).
    """
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
    except Exception as e:
        return None, str(e)

    row = (res.data or [None])[0]
    if not row:
        return None, None

    # Normalize possible column names
    plan = row.get("plan") or row.get("tier") or row.get("plan_code") or row.get("subscription_plan")
    status = row.get("status") or row.get("subscription_status") or row.get("state")

    expiry_raw = (
        row.get("plan_expiry")
        or row.get("plan_expiry_at")
        or row.get("expires_at")
        or row.get("expiry_at")
        or row.get("current_period_end")
        or row.get("period_end")
    )
    expiry_dt = _parse_dt(expiry_raw)
    is_active = row.get("is_active")
    if isinstance(is_active, bool):
        active = is_active
    else:
        active = _is_active_from_expiry(expiry_dt)

    return (
        {
            "known": True,
            "source": table_name,
            "plan": plan,
            "status": status,
            "plan_expiry": expiry_dt.isoformat() if expiry_dt else None,
            "is_active": bool(active),
            "raw": row,
        },
        None,
    )


def get_plan_status(auth_user_id: Optional[str]) -> Dict[str, Any]:
    """
    Best-effort subscription status lookup.
    - DOES NOT FAIL the caller if subscription tables differ/missing.
    - Returns {known:false} if nothing found.
    """
    auth_user_id = (auth_user_id or "").strip()
    if not auth_user_id:
        return {"known": False, "is_active": False, "plan": None, "status": None, "plan_expiry": None}

    # Try common table names in order of likelihood.
    # You can add/remove names here without touching API routes.
    candidates = [
        "subscriptions",
        "user_subscriptions",
        "user_plans",
        "plans",
    ]

    last_errors = []
    for t in candidates:
        plan_obj, err = _try_fetch_plan_from_table(t, auth_user_id)
        if err:
            last_errors.append({"table": t, "error": err})
            continue
        if plan_obj:
            # Hide raw row if you don’t want it returned publicly
            # (keeping it is useful while you’re still validating schema)
            return {"ok": True, **plan_obj}

    return {
        "ok": True,
        "known": False,
        "is_active": False,
        "plan": None,
        "status": None,
        "plan_expiry": None,
        "notes": "No subscription record found (or tables not present).",
        "debug_errors": last_errors[:2],  # keep small; prevents huge responses
    }
