# app/routes/subscription_routes.py
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, request, jsonify
from app.core.supabase_client import supabase  # ✅ keep consistent everywhere

bp = Blueprint("subscription", __name__)
log = logging.getLogger(__name__)

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
    Accounts table only.
    Unique key: (provider, provider_user_id)
    Expected PK column: id
    """
    provider = _normalize_provider(provider)
    provider_user_id = (provider_user_id or "").strip()
    if not provider_user_id:
        raise ValueError("provider_user_id is required")

    # Normalize only web ids to digits
    if provider == "web":
        provider_user_id = _digits(provider_user_id)

    # 1) lookup
    r = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    if rows:
        return str(rows[0]["id"])

    # 2) create
    ins = (
        supabase()
        .table("accounts")
        .insert(
            {
                "provider": provider,
                "provider_user_id": provider_user_id,
                "phone_e164": None,
            }
        )
        .execute()
    )
    created = getattr(ins, "data", None) or []
    if created and created[0].get("id"):
        return str(created[0]["id"])

    # 3) retry read (race-safe)
    r2 = (
        supabase()
        .table("accounts")
        .select("id")
        .eq("provider", provider)
        .eq("provider_user_id", provider_user_id)
        .limit(1)
        .execute()
    )
    rows2 = getattr(r2, "data", None) or []
    if rows2:
        return str(rows2[0]["id"])

    raise RuntimeError("Failed to resolve account id")

def _get_subscription_by_acct_key(acct_key: str) -> Optional[Dict[str, Any]]:
    r = (
        supabase()
        .table("user_subscriptions")
        .select("wa_phone,plan,status,expires_at,paystack_reference,updated_at")
        .eq("wa_phone", acct_key)
        .limit(1)
        .execute()
    )
    rows = getattr(r, "data", None) or []
    return rows[0] if rows else None

def _status_from_row(row: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not row:
        return {"status": "none", "plan": None, "expires_at": None, "reference": None}

    plan = row.get("plan")
    expires_at = row.get("expires_at")
    reference = row.get("paystack_reference")

    status = (row.get("status") or "").strip().lower()
    # Only treat active/paid as active candidates
    if status not in ("active", "paid"):
        return {"status": "none", "plan": plan, "expires_at": expires_at, "reference": reference}

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
    Body (new):
      { "provider": "web|wa|tg", "provider_user_id": "..." }

    Body (legacy fallback):
      { "wa_phone": "234..." } => treated as web digits
    """
    body = request.get_json(silent=True) or {}

    provider = (body.get("provider") or "").strip()
    provider_user_id = (body.get("provider_user_id") or "").strip()

    if not provider_user_id:
        wa_phone = _digits(body.get("wa_phone") or body.get("phone") or body.get("user_key") or "")
        if wa_phone:
            provider = "web"
            provider_user_id = wa_phone

    if not provider_user_id:
        return jsonify(ok=False, message="provider + provider_user_id (or wa_phone) is required"), 400

    try:
        acct_id = _resolve_acct_id(provider or "web", provider_user_id)
        acct_key = _acct_key(acct_id)

        row = _get_subscription_by_acct_key(acct_key)
        out = _status_from_row(row)

        return jsonify(
            ok=True,
            status=out["status"],
            plan=out["plan"],
            expires_at=out["expires_at"],
            reference=out["reference"],
            acct_id=acct_id,
            acct_key=acct_key,
        ), 200

    except Exception as e:
        log.exception("subscription/status failed: %s", e)
        return jsonify(ok=False, message="Unable to check status"), 500
