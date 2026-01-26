# app/routes/ask.py
import logging
from flask import Blueprint, request, jsonify

from app.services.engine import resolve_answer

bp = Blueprint("ask", __name__)


def _normalize_phone(p: str) -> str:
    return "".join(ch for ch in (p or "").strip() if ch.isdigit())


@bp.post("/ask")
def ask():
    data = request.get_json(silent=True) or {}

    wa_phone = _normalize_phone(str(data.get("wa_phone") or ""))
    question = str(data.get("question") or "").strip()
    mode = str(data.get("mode") or "text").strip()
    lang = str(data.get("lang") or "en").strip()

    if not wa_phone or not question:
        return jsonify
