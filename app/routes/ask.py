# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone

from app.services.engine import resolve_answer
from app.db.supabase_client import supabase

bp = Blueprint("ask", __name__)

# -----------------------------
# Helpers
# -----------------------------
def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


def _now_utc():
    return datetime.now(timezone.utc)


def _get_subscription(wa_phone: str):
    try:
        r = (
            supabase
            .table("user_subscriptions")
            .select("wa_phone, plan, status, expires_at, reference, paystack_reference")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )
        rows = getattr(r, "data", None) or []
        return rows[0] if rows else None
    except Exception as e:
        logging.exception("subscription lookup failed: %s", e)
        return None


def _is_active(sub: dict) -> bool:
    if not sub:
        return False

    status = (sub.get("status") or "").lower().strip()
    if status not in ("active", "paid"):
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
# ASK (AI)
# -----------------------------
@bp.post("/ask")
def ask():
    data = request.get_json(silent=True) or {}

    # allow wa_phone (web/whatsapp/telegram)
    wa_phone = _normalize_phone(data.get("wa_phone") or data.get("user_key") or data.get("phone") or "")
    question = str(data.get("question") or "").strip()
    mode = str(data.get("mode") or "text").strip()
    lang = str(data.get("lang") or "en").strip()

    if not wa_phone or not question:
        return jsonify({"ok": False, "message": "wa_phone and question are required"}), 400

    logging.info("ASK wa_phone=%s lang=%s mode=%s q=%s", wa_phone, lang, mode, question[:200])

    # Resolve answer (engine should enforce plan rules + compute expiry if needed)
    res = resolve_answer(
        wa_phone=wa_phone,
        question=question,
        mode=mode,
        lang=lang,
        source="web",
    )

    # Prefer engine's plan_expiry if provided; otherwise derive from subscription
    plan_expiry = res.get("plan_expiry")
    if not plan_expiry:
        sub = _get_subscription(wa_phone)
        if sub:
            plan_expiry = sub.get("expires_at")

    return jsonify(
        {
            "ok": True,
            "answer": res.get("answer_text"),
            "audio_url": None,
            "plan_expiry": plan_expiry,
            "source": res.get("source"),
        }
    ), 200


# -----------------------------
# SUBSCRIPTION STATUS ✅
# -----------------------------
@bp.post("/subscription/status")
def subscription_status():
    """
    Unified subscription status check.
    Your Next.js route (/api/subscription/status) proxies to:
      POST {API_BASE_URL}/subscription/status
    Body:
      { "wa_phone": "2348012345678" }
    """
    data = request.get_json(silent=True) or {}

    wa_phone = _normalize_phone(data.get("wa_phone") or data.get("user_key") or data.get("phone") or "")
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
                "reference": None,
            }
        ), 200

    active = _is_active(sub)

    # prefer reference, fallback to paystack_reference
    reference = sub.get("reference") or sub.get("paystack_reference")

    return jsonify(
        {
            "ok": True,
            "status": "active" if active else "expired",
            "plan": sub.get("plan"),
            "expires_at": sub.get("expires_at"),
            "reference": reference,
        }
    ), 200
