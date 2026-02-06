# app/services/accounts_service.py
from __future__ import annotations

from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timezone

from app.core.supabase_client import supabase


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    return expiry > datetime.now(timezone.utc)


# ---------------------------------------------------------
# Accounts: upsert / link / lookup
# ---------------------------------------------------------
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

    Safety rule:
    - If the channel is already linked to ANOTHER auth_user_id, block.
    - If linked to SAME auth_user_id, idempotent OK.
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

    # Guard: do not overwrite existing link to another user
    existing = lookup_account(provider=provider, provider_user_id=provider_user_id)
    if existing.get("ok") and existing.get("found"):
        old = (existing.get("auth_user_id") or "").strip()
        if old and old != auth_user_id:
            return {
                "ok": False,
                "error": "This channel is already linked to another account.",
                "reason": "channel_already_linked",
            }

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


# ---------------------------------------------------------
# Plan status: BEST PRACTICE LOOKUP (YOUR DB FIX)
# ---------------------------------------------------------
def _plan_from_subscriptions_table(auth_user_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Your actual table: public.subscriptions
    Columns seen:
      user_id, plan, status, start_at, end_at, paystack_ref, amount_kobo, currency, updated_at ...
    """
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
    active = False
    status = (row.get("status") or "").strip().lower() or None

    # Active decision: end_at in future OR status says active
    if end_dt and end_dt > datetime.now(timezone.utc):
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
    """
    Best-effort fallback for other possible tables if you create them later.
    Tries BOTH auth_user_id and user_id columns.
    """
    # try auth_user_id first
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
    except Exception as e_auth:
        auth_err = str(e_auth)
    else:
        auth_err = None

    # then try user_id
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
    except Exception as e_user:
        user_err = str(e_user)
    else:
        user_err = None

    # if both failed, return error summary
    err = auth_err or user_err
    return None, err


def get_plan_status(auth_user_id: Optional[str]) -> Dict[str, Any]:
    """
    Best-practice plan status lookup for your current DB.
    - First checks: public.subscriptions(user_id,...)
    - Then tries: user_subscriptions / user_plans / plans (future compatibility)
    - NEVER breaks your API if tables/columns differ.
    """
    auth_user_id = (auth_user_id or "").strip()
    if not auth_user_id:
        return {"ok": True, "known": False, "is_active": False, "plan": None, "status": None, "plan_expiry": None}

    # 1) Your actual table first
    plan_obj, err = _plan_from_subscriptions_table(auth_user_id)
    if err is None and plan_obj:
        return {"ok": True, **plan_obj}
    debug_errors = []
    if err:
        debug_errors.append({"table": "subscriptions", "error": err})

    # 2) Fallback tables (safe)
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
