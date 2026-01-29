# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.services.engine import resolve_answer
from app.db.supabase_client import supabase  # <-- this is now a FUNCTION

bp = Blueprint("ask", __name__)


def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _get_subscription(user_key: str) -> Optional[Dict[str, Any]]:
    try:
        r = (
            supabase()
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


@bp.post("/ask")
def ask():
    data = request.get_json(silent=True) or {}

    raw_key = str(data.get("wa_phone") or data.get("user_key") or "").strip()
    user_key = _normalize_phone(raw_key)

    question = str(data.get("question") or "").strip()
    mode = str(data.get("mode") or "text").strip()
    lang = str(data.get("lang") or "en").strip()

    if not user_key or not question:
        return jsonify({"ok": False, "message": "wa_phone (or user_key) and question are required"}), 400

    sub = _get_subscription(user_key)
    active = _is_active(sub)

    logging.info("ASK user_key=%s active=%s lang=%s mode=%s q=%s",
                 user_key, active, lang, mode, question[:200])

    res = resolve_answer(
        wa_phone=user_key,
        question=question,
        mode=mode,
        lang=lang,
        source="web",
    )

    return jsonify(
        {
            "ok": True,
            "answer": res.get("answer_text"),
            "audio_url": res.get("audio_url"),
            "plan_expiry": res.get("plan_expiry"),
            "source": res.get("source"),
        }
    ), 200
