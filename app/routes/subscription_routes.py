# app/routes/subscription_routes.py
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, request, jsonify
from app.db.supabase_client import supabase  # function: supabase().table(...)

bp = Blueprint("subscription", __name__)

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _normalize_provider(p: str) -> str:
    v = (p or "").strip().lower()
    if v in ("wa", "whatsapp"):
        return "wa"
    if v in ("tg", "telegram"):
        return "tg"
    return "web"

def _digits(x: str) -> str:
    return "".join(ch for ch in (x or "").strip() if ch.isdigit())

def _acct_key(acct_id: str) -> str:
    return f"acct:{acct_id}"

def _resolve_acct_id(provider: str, provider_user_id: str) -> str:
    """
    Accounts table only (no Supabase Auth).
    Unique key: (provider, provider_user_id)
    """
    provider = _normalize_provider(provider)
    provider_user_id = (provider_user_id or "").strip()
    if not provider_user_id:
        raise ValueError("provider_user_id is required")

    # 1) lookup
    r = (
        supabase()
        .table("accounts")
        .select("acct_id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return str(rows[0]["acct_id"])

    # 2) create
    ins = (
        supabase()
        .table("accounts")
        .insert(
            {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "status": "active",
                "updated_at": _now_utc().isoformat(),
            }
        )
        .execute()
    )
    created = getattr(ins, "data", None) or []
    if created and created[0].get("acct_id"):
        return str(created[0]["acct_id"])

    # 3) retry read (race-safe)
    r2 = (
        supabase()
        .table("accounts")
        .select("acct_id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows2 = getattr(r2, "data", None) or []
    if rows2:
        return str(rows2[0]["acct_id"])

    raise RuntimeError("Failed to resolve acct_id")

def _get_subscription_by_acct_key(acct_key: str) -> Optional[Dict[str, Any]]:
    try:
        r = (
            supabase()
            .table("user_subscriptions")
            .select("*")
            .eq("wa_phone", acct_key)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None

def _status_from_row(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not row:
        return {"status": "none", "plan": None, "expires_at": None, "reference": None}

    plan = row.get("plan")
    expires_at = row.get("expires_at")
    reference = row.get("paystack_reference") or row.get("reference")

    # active vs expired
    status = (row.get("status") or "").strip().lower()
    if status not in ("active", "paid"):
        # if pending, show none/expired based on expires
        return {
            "status": "none",
            "plan": plan,
            "expires_at": expires_at,
            "reference": reference,
        }

    if not expires_at:
        return {"status": "expired", "plan": plan, "expires_at": None, "reference": reference}

    try:
        exp_dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if exp_dt > _now_utc():
            return {"status": "active", "plan": plan, "expires_at": expires_at, "reference": reference}
        return {"status": "expired", "plan": plan, "expires_at": expires_at, "reference": reference}
    except Exception:
        return {"status": "expired", "plan": plan, "expires_at": expires_at, "reference": reference}

@bp.post("/subscription/status")
def subscription_status():
    """
    NEW:
      { "provider": "web|wa|tg", "provider_user_id": "..." }

    OLD fallback:
      { "wa_phone": "234..." } -> treated as web identity digits
    """
    body = request.get_json(silent=True) or {}

    provider = (body.get("provider") or "").strip()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if not provider_user_id:
        # backward compat
        wa_phone = _digits(body.get("wa_phone") or body.get("phone") or body.get("user_key") or "")
        if wa_phone:
            provider = "web"
            provider_user_id = wa_phone

    if not provider_user_id:
        return jsonify({"ok": False, "message": "provider + provider_user_id (or wa_phone) is required"}), 400

    try:
        acct_id = _resolve_acct_id(provider or "web", provider_user_id)
        acct_key = _acct_key(acct_id)

        row = _get_subscription_by_acct_key(acct_key)
        out = _status_from_row(row)

        return jsonify(
            {
                "ok": True,
                "status": out["status"],
                "plan": out["plan"],
                "expires_at": out["expires_at"],
                "reference": out["reference"],
                "acct_id": acct_id,
                "acct_key": acct_key,
            }
        ), 200
    except Exception as e:
        logging.exception("subscription/status failed: %s", e)
        return jsonify({"ok": False, "message": "Unable to check status"}), 500
