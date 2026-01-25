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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _get_subscription(wa_phone: str):
    try:
        r = (
            supabase
            .table("user_subscriptions")
            .select("*")
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

    status = (sub.get("status") or "").strip().lower()
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

    wa_phone = _normalize_phone(str(data.get("wa_phone") or ""))
    question = str(data.get("question") or "").strip()
    mode = str(data.get("mode") or "text").strip()
    lang = str(data.get("lang") or "en").strip()

    if not wa_phone or not question:
        return jsonify({"ok": False, "message": "wa_phone and question are required"}), 400

    logging.info("ASK wa_phone=%s lang=%s mode=%s q=%s", wa_phone, lang, mode, question[:200])

    res = resolve_answer(
        wa_phone=wa_phone,
        question=question,
        mode=mode,
        lang=lang,
        source="web",
    )

    # You said: "users should only see plan expiry" (no credits counters)
    return jsonify({
        "ok": True,
        "answer": res.get("answer_text"),
        "audio_url": None,
        "plan_expiry": res.get("plan_expiry"),
        "source": res.get("source"),
    }), 200


# -----------------------------
# SUBSCRIPTION STATUS
# -----------------------------
@bp.post("/subscription/status")
def subscription_status():
    """
    Unified subscription status check.
    Works for WhatsApp / Telegram / Web using ONE identity.
    Request:
      { "wa_phone": "2348012345678" }
    """
    data = request.get_json(silent=True) or {}
    wa_phone = _normalize_phone(str(data.get("wa_phone") or ""))

    if not wa_phone:
        return jsonify({"ok": False, "message": "wa_phone is required"}), 400

    sub = _get_subscription(wa_phone)

    if not sub:
        return jsonify({
            "ok": True,
            "status": "none",
            "plan": None,
            "expires_at": None,
            "reference": None,
        }), 200

    active = _is_active(sub)

    return jsonify({
        "ok": True,
        "status": "active" if active else "expired",
        "plan": sub.get("plan"),
        "expires_at": sub.get("expires_at"),
        "reference": sub.get("reference"),
    }), 200
