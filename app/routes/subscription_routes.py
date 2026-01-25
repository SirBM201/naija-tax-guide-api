# app/routes/subscription_routes.py
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, request, jsonify

bp = Blueprint("subscription", __name__)


def _db():
    from app.db.supabase_client import supabase as get_supabase
    return get_supabase()


def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(dt_str: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(dt_str).replace("Z", "+00:00"))
    except Exception:
        return None


def _get_subscription(wa_phone: str) -> Optional[Dict[str, Any]]:
    try:
        r = (
            _db()
            .table("user_subscriptions")
            .select("wa_phone,plan,status,expires_at,updated_at")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None


@bp.post("/subscription/status")
def subscription_status():
    """
    Request JSON:
      { "wa_phone": "2348012345678" }

    Response:
      { ok: true, status, plan, expires_at }
      { ok: false, message }
    """
    body = request.get_json(silent=True) or {}
    wa_phone = _normalize_phone(body.get("wa_phone") or "")

    if not wa_phone:
        return jsonify({"ok": False, "message": "wa_phone is required"}), 400

    sub = _get_subscription(wa_phone)
    if not sub:
        return jsonify(
            {
                "ok": True,
                "status": "none",
                "plan": None,
                "expires_at": None,
            }
        ), 200

    status = (sub.get("status") or "").strip().lower() or "unknown"
    plan = (sub.get("plan") or "").strip().lower() or None
    expires_at = sub.get("expires_at")

    # normalize active/expired using expires_at
    exp_dt = _parse_iso(expires_at) if expires_at else None
    if exp_dt and exp_dt <= _now_utc():
        status = "expired"

    return jsonify(
        {
            "ok": True,
            "status": status,
            "plan": plan,
            "expires_at": expires_at,
        }
    ), 200
