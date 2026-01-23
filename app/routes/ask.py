# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging

from app.services.engine import resolve_answer

bp = Blueprint("ask", __name__)

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
        "plan_expiry": None,  # if your existing code adds it elsewhere, keep your current logic
    })
