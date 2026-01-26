# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging

from app.services.engine import resolve_answer

bp = Blueprint("ask", __name__)


def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


@bp.post("/ask")
def ask():
    data = request.get_json(silent=True) or {}

    wa_phone = _normalize_phone(str(data.get("wa_phone") or data.get("user_key") or ""))
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

    return jsonify(
        {
            "ok": True,
            "answer": res.get("answer_text"),
            "audio_url": None,
            # engine may return plan_expiry if you’ve implemented it; safe to return as-is
            "plan_expiry": res.get("plan_expiry"),
            "source": res.get("source"),
        }
    ), 200
