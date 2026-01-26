# app/routes/subscription_routes.py
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from flask import Blueprint, request, jsonify

from app.db.supabase_client import supabase

bp = Blueprint("subscription", __name__)


# -----------------------------
# Helpers
# -----------------------------
def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _get_subscription(user_key: str) -> Optional[Dict[str, Any]]:
    """
    user_key is the ONE identity you use across Web/WhatsApp/Telegram.
    For now you are storing it in user_subscriptions.wa_phone.
    """
    try:
        r = (
            supabase
            .table("user_subscriptions")
            .select("*")
            .eq("wa_phone", user_key)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None


def _is_active(sub: Optional[Dict[str, Any]]) -> bool:
    if not sub:
        return False

    status = (sub.get("status") or "").strip().lower()
    # accept both "active" and "paid"
    if status and status not in ("active", "paid"):
        return False

    exp = sub.get("expires_at")
    if not exp:
        return False

    try:
        exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        return exp_dt > _now_utc()
    except Exception:
        return False


# -----------------------------
# SUBSCRIPTION STATUS
# -----------------------------
@bp.post("/subscription/status")
def subscription_status():
    """
    Request JSON:
      { "wa_phone": "2348012345678" }

    Response:
      {
        ok: true,
        status: "active" | "expired" | "none",
        plan: "monthly|quarterly|yearly"|null,
        expires_at: "...iso..."|null,
        reference: "...optional..."|null
      }
    """
    data = request.get_json(silent=True) or {}

    # Accept either wa_phone or user_key to avoid frontend mismatch
    raw_key = str(data.get("wa_phone") or data.get("user_key") or "").strip()
    user_key = _normalize_phone(raw_key)

    if not user_key:
        return jsonify({"ok": False, "message": "wa_phone is required"}), 400

    sub = _get_subscription(user_key)

    if not sub:
        return jsonify(
            {
                "ok": True,
                "status": "none",
                "plan": None,
                "expires_at": None,
                "reference": None,
            }
        ), 200

    active = _is_active(sub)

    return jsonify(
        {
            "ok": True,
            "status": "active" if active else "expired",
            "plan": sub.get("plan"),
            "expires_at": sub.get("expires_at"),
            "reference": sub.get("reference") or sub.get("paystack_reference") or None,
        }
    ), 200
