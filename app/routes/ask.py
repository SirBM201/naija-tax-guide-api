# app/routes/ask.py
from flask import Blueprint, request, jsonify
import logging

from app.core.utils import normalize_phone
from app.db.subscriptions import get_plan_expiry_iso
from app.services.engine import resolve_answer  # created below

bp = Blueprint("ask", __name__)

@bp.post("/ask")
def ask():
    body = request.get_json(silent=True) or {}
    wa_phone = normalize_phone(body.get("wa_phone") or "")
    question = (body.get("question") or "").strip()

    lang = (body.get("lang") or body.get("language") or "en").strip().lower()
    mode = (body.get("mode") or "text").strip().lower()
    if mode not in ("text", "voice"):
        mode = "text"

    voice_provider = (body.get("voice_provider") or "openai").strip().lower()
    voice_style = (body.get("voice_style") or "default").strip().lower()

    if not wa_phone:
        return jsonify({"ok": False, "error": "wa_phone is required"}), 400
    if not question:
        return jsonify({"ok": False, "error": "question is required"}), 400

    logging.info("ASK wa_phone=%s lang=%s mode=%s q=%s", wa_phone, lang, mode, question[:200])
    result = resolve_answer(
        wa_phone=wa_phone,
        question=question,
        mode=mode,
        voice_provider=voice_provider,
        voice_style=voice_style,
        lang=lang,
        source="web",
    )

    return jsonify({
        "ok": True,
        "answer": result.get("answer_text"),
        "audio_url": result.get("audio_url"),
        "plan_expiry": get_plan_expiry_iso(wa_phone),
    })
