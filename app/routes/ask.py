# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone

from app.services.engine import resolve_answer

bp = Blueprint("ask", __name__)


def _db():
    # Uses your existing Supabase client
    from app.db.supabase_client import supabase
    return supabase


def _now_utc():
    return datetime.now(timezone.utc)


def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


@bp.post("/ask")
def ask():
    data = request.get_json(silent=True) or {}

    wa_phone = str(data.get("wa_phone") or "").strip()
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

    return jsonify({
        "ok": True,
        "answer": res.get("answer_text"),
        "audio_url": None,
        "plan_expiry": None,
        "source": res.get("source"),  # nice for debugging
    }), 200


@bp.post("/subscription/status")
def subscription_status():
    """
    Request JSON:
      { "wa_phone": "2348012345678" }

    Response:
      { ok: true, status: "active|expired|none", plan, expires_at, reference }
    """
    body = request.get_json(silent=True) or {}
    wa_phone = _normalize_phone(body.get("wa_phone") or "")

    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400

    try:
        r = (
            _db()
            .table("user_subscriptions")
            .select("status,plan,expires_at,reference")
            .eq("wa_phone", wa_phone)
            .limit(1)
            .execute()
        )

        rows = getattr(r, "data", None) or []
        if not rows:
            return jsonify({
                "ok": True,
                "status": "none",
                "plan": None,
                "expires_at": None,
                "reference": None,
            }), 200

        sub = rows[0]
        expires_at = sub.get("expires_at")

        is_active = False
        if expires_at:
            try:
                exp = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
                is_active = exp > _now_utc()
            except Exception:
                is_active = False

        return jsonify({
            "ok": True,
            "status": "active" if is_active else "expired",
            "plan": sub.get("plan"),
            "expires_at": expires_at,
            "reference": sub.get("reference"),
        }), 200

    except Exception:
        logging.exception("subscription_status failed")
        return jsonify({"ok": False, "error": "Unable to fetch subscription status"}), 500
